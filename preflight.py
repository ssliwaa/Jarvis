#!/usr/bin/env python3
"""LIVE production preflight: real HTTP, real model calls, real files and Chromium.

Run: python3 preflight.py (automatically uses this project's .venv if needed).
No fixture vaults, replaced transports, synthetic speech engines or skipped checks.
The disposable capture is removed through a narrowly scoped live cleanup endpoint.
Append a (stable_id, label, method_name) entry to CHECKS for each future live chain.
"""
from __future__ import annotations

import argparse
import ast
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import socket
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from provider_client import (
    DEEPSEEK_BALANCE_URL,
    RETIRED_MODELS,
    ProviderError,
    load_deepseek_key,
    make_client,
)

ROOT = Path(__file__).resolve().parent
from jarvis_paths import resolve_config_path
CHECKS = (
    ('server', 'Server and viewer', 'check_server'),
    ('graph', 'Graph data and live renderer', 'check_graph'),
    ('chat', 'Real /chat answer', 'check_chat'),
    ('capabilities', 'Capability manifest and truthful prompt', 'check_capabilities'),
    ('routing', 'Chat routing, destructive gate and path redaction', 'check_chat_routing'),
    ('retrieval', 'FTS5 retrieval index', 'check_retrieval'),
    ('key', 'Configured API key', 'check_key'),
    ('model', 'Configured model access', 'check_model'),
    ('remember', 'Live /remember → recall → cleanup', 'check_remember'),
    ('files', 'Served files match disk', 'check_files'),
    ('config', 'PRIVATE CONFIG MUST NOT BE SERVED', 'check_config'),
    ('mute', '?mute=1 speech refusal', 'check_mute'),
    ('voice', 'Browser voice controls', 'check_voice'),
    ('tts', 'Edge TTS neural voice', 'check_tts'),
    ('agent', 'Browser agent lane', 'check_agent'),
    ('p1', 'Memory, sessions, skills and MCP', 'check_p1'),
    ('p2', 'System, briefing, documents and organizer', 'check_p2'),
    ('p3', 'Supervisor, router, queue and suggestions', 'check_p3'),
    ('selfmod', 'Self-modification lane', 'check_selfmod'),
    ('teardown', 'Reverse-engineering bay (REA)', 'check_teardown'),
    ('browser', 'Ephemeral Chrome teardown browser', 'check_browser'),
    ('evidence', 'Live evidence capture (REA + Jarvis)', 'check_evidence'),
    ('teardown_note', 'Teardown note index and births', 'check_teardown_note'),
    ('teardown_panel', 'Teardown routes, card and reader', 'check_teardown_panel'),
    ('kit', 'Teardown kit ready with pinned REA', 'check_kit'),
    ('offline', 'Offline teardown checks', 'check_offline'),
    ('chrome_clean', 'No investigation Chrome remains', 'check_chrome_clean'),
    ('webbackends', 'Isolated crawl4ai/Scrapling reader', 'check_webbackends'),
    ('context', 'Bounded tool payloads', 'check_context'),
    ('checkpoints', 'File checkpoints (shadow git)', 'check_checkpoints'),
    ('ocr', 'Layout OCR (tesseract blocks)', 'check_ocr'),
    ('planfiles', 'On-disk plan survives a restart', 'check_planfiles'),
    ('heartbeat', 'Opt-in silent heartbeat', 'check_heartbeat'),
    ('desktop_mcp', 'Linux desktop MCP', 'check_desktop_mcp'),
    ('vision', 'Approved image vision', 'check_vision'),
    ('wakeword', 'Local wake word', 'check_wakeword'),
    ('personal_briefing', 'Personal daily briefing', 'check_personal_briefing'),
    ('watch_pages', 'Opt-in page and price watches', 'check_watch_pages'),
    ('job_control', 'Voice control of running jobs', 'check_job_control'),
    ('account', 'Personal mail and calendar', 'check_account'),
    ('agents', 'External agent sandbox and consent', 'check_agents'),
    ('jev', 'Optional Jev decision layer', 'check_jev'),
    ('hardening', 'Operator hardening: read guard, scrub, loop, archive', 'check_hardening'),
)

# Checks that touch no browser page, shared port or Operator job. Anything that
# drives a page, starts a job or owns a Chrome port must stay serial.
PARALLEL_CHECKS = frozenset({
    'server', 'key', 'model', 'tts', 'config',
    'capabilities', 'retrieval', 'offline', 'chrome_clean',
    'webbackends', 'context', 'checkpoints', 'ocr', 'planfiles', 'hardening',
})


class Failure(Exception):
    pass


class WarningVerdict(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward bearer credentials or disguise a wrong URL.


class PageAssets(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.ids, self.urls = set(), []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.add(attrs['id'])
        if tag == 'script' and attrs.get('src'):
            self.urls.append(attrs['src'])
        if tag == 'link' and attrs.get('rel') in ('stylesheet', 'icon') and attrs.get('href'):
            self.urls.append(attrs['href'])


class Preflight:
    def __init__(self, base_url='http://127.0.0.1:4700', timeout=195, report=None):
        parsed = urlsplit(base_url)
        require(parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost')
                and parsed.path in ('', '/') and not parsed.query and not parsed.fragment
                and parsed.username is None and parsed.password is None,
                '--url must be an HTTP loopback origin, without credentials or a path')
        self.base = base_url.rstrip('/')
        self.timeout = timeout
        self.report = Path(report) if report else ROOT / 'artifacts/preflight.json'
        self.pending_path = ROOT / 'artifacts/preflight-pending.json'
        self.http = build_opener(NoRedirect())
        self.key, self.model, self.config_hash = '', '', None
        self.provider = 'deepseek'
        self.graph, self.html = None, None
        self.playwright = self.browser = self.context = self.page = None
        self.page_errors, self.responses, self.results = [], [], []
        self.panel_fixture = None

    def safe(self, message):
        text = str(message)
        if self.key:
            text = text.replace(self.key, '[REDACTED]')
        return re.sub(r'\bsk-[A-Za-z0-9_-]{12,}', '[REDACTED]', text)[:1200].replace('\n', ' ')

    def request(self, url, payload=None, headers=None, timeout=None):
        data = json.dumps(payload).encode('utf-8') if payload is not None else None
        request = Request(url, data=data, headers={'Accept': 'application/json',
                          **({'Content-Type': 'application/json'} if data is not None else {}), **(headers or {})})
        try:
            response = self.http.open(request, timeout=timeout or self.timeout)
        except HTTPError as error:
            response = error
        except (URLError, TimeoutError, OSError) as error:
            raise Failure(f'Connection failed ({type(error).__name__}) for {urlsplit(url).path}') from None
        with response:
            raw = response.read(20 * 1024 * 1024 + 1)
            require(len(raw) <= 20 * 1024 * 1024, 'Response exceeded the preflight size limit')
            return response.status, dict(response.headers), raw

    def local(self, path, payload=None, **kwargs):
        require(path.startswith('/') and not path.startswith('//'), 'Invalid local check path')
        return self.request(self.base + path, payload, **kwargs)

    def local_bytes(self, path, data, content_type):
        require(path.startswith('/') and not path.startswith('//'), 'Invalid local check path')
        request = Request(self.base + path, data=data, method='POST',
                          headers={'Accept': 'application/json', 'Content-Type': content_type})
        try:
            response = self.http.open(request, timeout=self.timeout)
        except HTTPError as error:
            response = error
        except (URLError, TimeoutError, OSError) as error:
            raise Failure(f'Connection failed ({type(error).__name__}) for {path}') from None
        with response:
            raw = response.read(4 * 1024 * 1024 + 1)
            require(len(raw) <= 4 * 1024 * 1024, 'Response exceeded the preflight size limit')
            return response.status, dict(response.headers), raw

    def local_json(self, path, payload=None):
        status, _, raw = self.local(path, payload)
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Failure(f'{path}: HTTP {status}, not JSON') from None
        code = data.get('error', {}).get('code', '') if isinstance(data, dict) and isinstance(data.get('error', {}), dict) else ''
        require(200 <= status < 300, f'{path}: HTTP {status} {code}')
        return data

    def provider_json(self, path):
        self.configuration()
        status, _, raw = self.request('https://openrouter.ai/api/v1' + path,
                                     headers={'Authorization': 'Bearer ' + self.key}, timeout=min(self.timeout, 30))
        require(status == 200, f'OpenRouter {path}: HTTP {status}')
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Failure(f'OpenRouter {path}: response was not JSON') from None
        require(isinstance(result, dict) and 'data' in result, f'OpenRouter {path}: missing data')
        return result['data']

    def configuration(self):
        if self.config_hash is not None:
            return
        try:
            raw = resolve_config_path(ROOT).read_bytes()
            config = json.loads(raw)
            provider = config.get('provider')
            if provider is None:
                legacy = 'aOPENROUTER_API_KEY' in config or 'OPENROUTER_API_KEY' in config
                provider = 'openrouter' if legacy else 'deepseek'
            model = config['model']
            if provider == 'deepseek':
                key = load_deepseek_key()
            else:
                key = config['aOPENROUTER_API_KEY']
        except (OSError, ValueError, TypeError, KeyError):
            raise Failure('Root config.json is missing or invalid; expected provider, model and a key source') from None
        require(provider in ('deepseek', 'openrouter'), 'Configured provider is invalid')
        pattern = (r'[A-Za-z0-9_.-]+/[A-Za-z0-9_./:-]+' if provider == 'openrouter'
                   else r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./:-]+)?')
        require(isinstance(model, str) and len(model) <= 200
                and re.fullmatch(pattern, model),
                f'Invalid configured model id: {model!r}')
        require(model not in RETIRED_MODELS,
                f'Configured model {model!r} was retired on 2026-07-24; '
                'use deepseek-flash or deepseek-v4-pro')
        if provider == 'deepseek':
            require(isinstance(key, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{16,512}', key),
                    'DEEPSEEK_API_KEY is missing from the Hermes environment')
        else:
            require(isinstance(key, str) and re.fullmatch(r'sk-or-[A-Za-z0-9_-]{20,256}', key),
                    'Configured OpenRouter key has an invalid format')
        self.key, self.model, self.provider = key, model, provider
        self.config_hash = hashlib.sha256(raw).hexdigest()

    def get_graph(self):
        status, _, raw = self.local('/graph-data.js')
        require(status == 200, f'/graph-data.js: HTTP {status}')
        try:
            match = re.fullmatch(r'\s*const\s+GRAPH\s*=\s*(\{.*\})\s*;?\s*', raw.decode('utf-8'), re.S)
            graph = json.loads(match.group(1)) if match else None
        except (ValueError, UnicodeError):
            graph = None
        require(isinstance(graph, dict) and isinstance(graph.get('nodes'), list) and isinstance(graph.get('links'), list), 'Served GRAPH is malformed')
        require(all(isinstance(n, dict) and type(n.get('id')) is int and n['id'] == i for i, n in enumerate(graph['nodes'])), 'Graph node ids do not equal their array indexes')
        require(all(isinstance(e, dict) and all(type(e.get(k)) is int and 0 <= e[k] < len(graph['nodes']) for k in ('source','target')) for e in graph['links']), 'Graph contains invalid link indexes')
        return graph

    def ensure_page(self):
        if self.page is not None:
            return self.page
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise Failure('Playwright is required for the live browser checks; install it in .venv and install Chromium') from None
        self.playwright = sync_playwright().start()
        try:
            # Native APIs, with an audio-output safety belt; no speech engine replacement.
            self.browser = self.playwright.chromium.launch(headless=True,
                args=['--enable-unsafe-swiftshader','--use-angle=swiftshader','--mute-audio'])
            self.context = self.browser.new_context(viewport={'width':1280,'height':900})
            self.page = self.context.new_page()
            self.page.on('pageerror', lambda error: self.page_errors.append(self.safe(error.stack or error)))
            self.page.on('response', lambda response: self.responses.append(response))
            self.page.goto(self.base + '/?mute=1', wait_until='networkidle', timeout=90000)
        except Exception as error:
            raise Failure(f'Live Chromium could not load the viewer ({type(error).__name__})') from None
        return self.page

    def wait_browser(self, expression, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.page.evaluate('() => (' + expression + ')'):
                return
            self.page.wait_for_timeout(50)
        raise Failure('Live browser condition timed out: ' + expression)

    def validate_answer(self, payload, graph=None):
        require(isinstance(payload, dict) and not payload.get('error'), 'The live brain returned an error instead of an answer')
        require(isinstance(payload.get('answer'), str) and bool(payload['answer'].strip()), 'The live brain returned an empty or malformed answer')
        nodes = payload.get('nodes')
        require(isinstance(nodes, list), 'The live brain did not return a nodes array')
        graph = graph if graph is not None else self.get_graph()
        require(all(type(i) is int and 0 <= i < len(graph['nodes']) for i in nodes), 'The live answer cites invalid source indexes')
        return payload

    def open_studio(self, tab=None):
        """Open the Studio sheet deterministically, whatever state a check left behind."""
        page = self.dismiss_overlays()
        if page.locator('#studio-panel').is_visible():
            page.locator('#studio-close').click()
            page.locator('#studio-panel').wait_for(state='hidden', timeout=10000)
        page.locator('#studio-toggle').click()
        page.locator('#studio-panel').wait_for(state='visible', timeout=10000)
        if tab:
            page.locator(f'[data-studio-tab="{tab}"]').click()
        return page

    def dismiss_overlays(self):
        """Close a capability overlay a failed check may have left covering the page."""
        page = self.ensure_page()
        try:
            if page.locator('#capability-overlay').is_visible():
                page.locator('#capability-close').click()
                page.locator('#capability-overlay').wait_for(state='hidden', timeout=10000)
        except Exception:
            pass
        try:
            if page.locator('#td-reader').is_visible():
                page.locator('#td-reader-close').click()
                page.locator('#td-reader').wait_for(state='hidden', timeout=10000)
        except Exception:
            pass
        return page

    def close_studio(self):
        page = self.ensure_page()
        try:
            if page.locator('#studio-panel').is_visible():
                page.locator('#studio-close').click()
                page.locator('#studio-panel').wait_for(state='hidden', timeout=10000)
        except Exception:
            pass
        return page

    def ask_ui(self, question):
        page = self.ensure_page()
        page.locator('#ask-button:not([disabled])').wait_for(state='visible', timeout=20000)
        page.locator('#question').fill(question)
        # The viewer uses the streaming lane first and only falls back to
        # /chat when SSE is unavailable. Waiting exclusively for /chat made
        # every live answer time out after the stream became primary.
        with page.expect_response(
                lambda response: urlsplit(response.url).path in ('/chat', '/chat/stream')
                and response.request.method == 'POST',
                timeout=self.timeout * 1000) as pending:
            page.locator('#ask-button').click()
        response = pending.value
        require(response.status == 200, f'/chat: HTTP {response.status}')
        if urlsplit(response.url).path == '/chat/stream':
            # Chromium does not keep the body of an SSE response available to
            # Playwright after the page consumed it. The rendered answer and
            # the live galaxy source set are the observable result instead.
            self.wait_browser('!galaxy.busy', timeout=60)
            state = page.evaluate(
                "() => ({answer: document.getElementById('chat-answer').textContent || '',"
                " nodes: Array.isArray(window.galaxy?.sourceIds) ? window.galaxy.sourceIds : []})")
            payload = {'answer': state['answer'], 'nodes': state['nodes']}
        else:
            try:
                payload = response.json()
            except Exception:
                raise Failure('/chat did not return JSON in the real browser') from None
            self.wait_browser('!galaxy.busy')
        require(page.locator('#chat-answer').inner_text() == payload.get('answer'), 'The browser did not display the returned answer')
        return self.validate_answer(payload)

    def check_server(self):
        status, headers, raw = self.local('/')
        require(status == 200 and 'text/html' in headers.get('Content-Type', ''), f'Viewer returned HTTP {status}, not the expected HTML')
        self.html = raw.decode('utf-8')
        assets = PageAssets(self.html)
        require({'graph','chat-form','question'} <= assets.ids, 'HTTP 200 is not the knowledge viewer')
        return 'HTTP 200; correct viewer HTML'

    def check_graph(self):
        self.graph = self.get_graph()
        require(len(self.graph['nodes']) > 0, 'The served graph has zero nodes')
        page = self.ensure_page()
        self.wait_browser('window.galaxy && (galaxy.ready || galaxy.error)', timeout=60)
        page.evaluate('''() => {
            if (window.galaxy?.graph?.renderer()?.info) {
                window.galaxy.graph.renderer().info.autoReset = false;
            }
        }''')
        for _ in range(50):
            state = page.evaluate('''() => ({ready:galaxy.ready,error:galaxy.error,nodes:galaxy.nodes.length,sprites:galaxy.sprites.size,calls:(galaxy.graph?.renderer()?.info?.render?.calls || galaxy.graph?.renderer()?.info?.render?.frame || 0)})''')
            if state.get('calls', 0) > 0 or state.get('error'):
                break
            page.wait_for_timeout(100)
        require(state['ready'] and state['nodes'] == len(self.graph['nodes']) and state['sprites'] == state['nodes'] and state['calls'] > 0,
                f'Live WebGL graph is not rendering: {state}')
        require(not self.page_errors, 'Browser script errors: ' + '; '.join(self.page_errors))
        return f"{len(self.graph['nodes'])} nodes, {len(self.graph['links'])} links; real WebGL rendered"

    def check_chat(self):
        graph = self.graph or self.get_graph()
        candidates = [n for n in graph['nodes'] if n.get('excerpt') and n.get('group') in ('concepts','entities')]
        note = next((n for n in candidates if n.get('label') == 'plan-treningowy-bieg'), candidates[0] if candidates else graph['nodes'][0])
        question = f'In the note titled "{note["label"]}", what is one concrete practical fact? Be brief.'
        answer = self.ask_ui(question)
        require(bool(answer['nodes']), 'A real question about an existing note returned no sources')
        small = self.ask_ui('say something')
        require(small.get('nodes') == [], 'A conversational prompt was forced to cite notes')
        require('notes are indexed' in small.get('answer', '').casefold(), 'The conversational fallback did not answer in character')
        return f"HTTP 200; nonempty answer and {len(answer['nodes'])} valid source index(es) displayed; small talk stayed local"

    def check_capabilities(self):
        health = self.local_json('/health')
        actual = hashlib.sha256((ROOT / 'server.py').read_bytes()).hexdigest()
        require(health.get('sources', {}).get('server.py') == actual,
                'STALE RUNNING BACKEND: server.py differs from disk; restart it before checking capabilities')
        live = self.local_json('/capabilities')
        import server
        expected = server.capability_manifest()
        require(live == expected, 'The live capability manifest disagrees with the running source')
        ids = {item.get('id') for item in (live.get('capabilities') or [])}
        require({'note_answers', 'capture_note', 'count_notes', 'clear_history', 'teardown_site'}.issubset(ids),
                'The live capability manifest is missing a real action')
        require(any('shell' in str(limit).casefold() and
                    ('approval' in str(limit).casefold() or 'unrestricted' in str(limit).casefold())
                    for limit in (live.get('limits') or [])),
                'The live capability manifest does not state the shell/desktop limit')
        require(all(item.get('label') in server.SYSTEM for item in live.get('capabilities', [])),
                'The prompt does not contain every live capability label')
        require('You cannot execute tools' not in server.SYSTEM,
                'The prompt still contains the stale blanket denial of tools')
        encoded = json.dumps(live, ensure_ascii=False)
        require('/home/' not in encoded and 'sk-or-' not in encoded,
                'The capability manifest exposed a local path or credential')
        return f"{len(ids)} capabilities, {len(live.get('limits') or [])} limits; live manifest == prompt registry"

    def check_chat_routing(self):
        """Chat must act, ask, or answer — never invent a path or a job."""
        health = self.local_json('/health')
        actual = hashlib.sha256((ROOT / 'server.py').read_bytes()).hexdigest()
        require(health.get('sources', {}).get('server.py') == actual,
                'STALE RUNNING BACKEND: server.py differs from disk; restart it before checking routing')
        import router as request_router
        require(request_router._classify_rules('Sprawdź ile wolnego miejsca jest na dysku')['action']
                == 'operator', 'A disk question is not routed to the Operator')
        require(request_router._classify_rules('Co dokładnie potrafisz?')['action'] == 'capabilities',
                'A capability question is not routed to the live registry')
        queue_before = self.local_json('/agent/queue').get('queue') or []
        destructive = self.local_json('/chat', {'question': 'Usuń wszystko z katalogu /tmp/jarvis-preflight'})
        require(destructive.get('outcome') == 'ask',
                f'A destructive chat request was not stopped (outcome={destructive.get("outcome")!r})')
        require(not destructive.get('operator'), 'A destructive chat request started an Operator job')
        require(len(self.local_json('/agent/queue').get('queue') or []) == len(queue_before),
                'A destructive chat request changed the Operator queue')
        caps = self.local_json('/chat', {'question': 'Co dokładnie potrafisz?'})
        require(bool(caps.get('capabilities')),
                'The capability question was not answered from the live registry')
        answer = str(caps.get('answer') or '')
        require('rejestr' in answer.casefold() or 'registry' in answer.casefold(),
                'The capability answer does not name its live source')
        import browser_agent
        home = str(Path.home())
        redacted = browser_agent._redact(home + '/.hermes/x.txt')
        require(redacted == '~/.hermes/x.txt',
                f'The public view no longer shortens the real home path (got {redacted!r})')
        return 'disk → Operator, destructive → ask without a job, capabilities from the registry, paths exact'

    def check_retrieval(self):
        graph = self.graph or self.get_graph()
        live = self.local_json('/retrieval/status')
        require(live.get('engine') == 'fts5', f"Live retrieval engine is {live.get('engine')!r}, not fts5")
        require(live.get('indexed_notes') == len(graph['nodes']),
                f"FTS5 indexed {live.get('indexed_notes')} notes but the graph has {len(graph['nodes'])}")
        require(live.get('fallback') is False, 'Live retrieval is using the keyword fallback')
        semantic = bool(live.get('semantic'))
        vectors = (live.get('vectors') or {}).get('rows')
        if semantic and vectors != live['indexed_notes']:
            # The lane is wired but the index is cold: build it once and prove
            # every note got a vector instead of accepting an empty table.
            built = self.local_json('/retrieval/vectors', {})
            require(built.get('rows') == live['indexed_notes'],
                    f"Vector index holds {built.get('rows')} rows for {live['indexed_notes']} notes")
            vectors = built.get('rows')
            live = self.local_json('/retrieval/status')
        encoded = json.dumps(live, ensure_ascii=False)
        require('/home/' not in encoded and 'Mars is' not in encoded,
                'The retrieval status leaked a local path or note content')
        if semantic:
            model = (live.get('vectors') or {}).get('model') or 'local model'
            return (f"FTS5 indexed {live['indexed_notes']} notes; semantic lane ready "
                    f"with {vectors} vectors ({model})")
        return f"FTS5 indexed {live['indexed_notes']} notes; keyword fallback available but inactive"

    def check_key(self):
        self.configuration()
        if self.provider == 'deepseek':
            status, _, raw = self.request(DEEPSEEK_BALANCE_URL,
                                          headers={'Authorization': 'Bearer ' + self.key},
                                          timeout=min(self.timeout, 30))
            require(status == 200, f'DeepSeek /user/balance: HTTP {status}')
            try:
                data = json.loads(raw)
            except (ValueError, UnicodeError):
                raise Failure('DeepSeek /user/balance: response was not JSON') from None
            require(isinstance(data, dict) and data.get('is_available') is True,
                    'DeepSeek key is not available')
            return 'Authenticated DeepSeek /user/balance returned HTTP 200; key not printed'
        data = self.provider_json('/key')
        require(isinstance(data, dict) and isinstance(data.get('label'), str), 'Authenticated key metadata was malformed')
        return 'Authenticated GET /api/v1/key returned HTTP 200; key not printed'

    def check_model(self):
        self.configuration()
        model = self.model  # Preserve the exact configured id; never substitute a fallback.
        if self.provider == 'deepseek':
            try:
                client = make_client('deepseek', self.key, timeout=min(self.timeout, 90))
                text = ''
                for budget in (2000, 4000):
                    response = client.messages.create(
                        model=model, max_tokens=budget,
                        system='This is a live connection check. Reply with OK.',
                        messages=[{'role': 'user', 'content': 'Reply with OK.'}], stream=False)
                    text = '\n'.join(block.text for block in response.content
                                     if getattr(block, 'type', '') == 'text').strip()
                    if text:
                        break
            except Failure as error:
                raise Failure(f'Model {model}: {error}') from None
            except ProviderError as error:
                raise Failure(f'Model {model}: DeepSeek call failed (HTTP {error.status_code})') from None
            except Exception as error:
                raise Failure(f'Model {model}: real minimal call failed ({type(error).__name__})') from None
            require(bool(text), 'Minimal inference returned no visible text after the larger-budget retry')
            return f'Model {model}: DeepSeek official API; minimal inference answered'
        try:
            details = self.provider_json('/model/' + quote(model, safe='/'))
            endpoints = self.provider_json('/models/' + quote(model, safe='/') + '/endpoints')
            require(isinstance(details, dict) and isinstance(details.get('id'), str), 'Models API by-id lookup returned malformed data')
            require(isinstance(endpoints, dict) and isinstance(endpoints.get('endpoints'), list) and bool(endpoints['endpoints']), 'Models API returned no reachable endpoints')
            import anthropic
            with anthropic.Anthropic(api_key=None, auth_token=self.key, base_url='https://openrouter.ai/api', max_retries=0, timeout=min(self.timeout,90)) as client:
                text = ''
                for budget in (2000,4000):
                    response = client.messages.create(model=model, max_tokens=budget, thinking={'type':'adaptive'},
                        output_config={'effort':'medium'}, system='This is a live connection check. Reply with OK.',
                        messages=[{'role':'user','content':'Reply with OK.'}], stream=False)
                    text = '\n'.join(block.text for block in response.content if block.type == 'text').strip()
                    if text:
                        break
            require(bool(text), 'Minimal inference returned no visible text after the larger-budget retry')
        except Failure as error:
            raise Failure(f'Model {model}: {error}') from None
        except Exception as error:
            status = getattr(error, 'status_code', None)
            raise Failure(f'Model {model}: real minimal call failed ({type(error).__name__}' + (f', HTTP {status}' if status else '') + ')') from None
        return f'Model {model}: by-id Models API found it; {len(endpoints["endpoints"])} endpoints; minimal inference answered'

    def save_pending(self, record):
        from build import atomic_write
        atomic_write(self.pending_path, json.dumps(record, sort_keys=True, indent=2).encode())

    def cleanup_probe(self, record):
        from build import NOTES_ROOT
        require(record.get('base') == self.base, 'Pending probe belongs to another server; refusing unsafe cleanup')
        probe_id = record['probe_id']
        require(str(uuid.UUID(probe_id)) == probe_id, 'Pending probe id is invalid')
        graph = self.get_graph()
        node = next((n for n in graph['nodes'] if n.get('group') == 'captures' and f'Temporary preflight probe {probe_id}: ' in n.get('excerpt', '')), None)
        if node is None:
            # Absence is only accepted if there is also no owned probe file left.
            captures = Path(NOTES_ROOT) / 'captures'
            if captures.exists():
                require(not captures.is_symlink(), 'Capture directory became a symlink; refusing cleanup')
                for candidate in captures.glob('*.md'):
                    require(not candidate.is_symlink(), 'Symlink in captures prevents a safe orphan check')
                    if f'\n\nTemporary preflight probe {probe_id}: ' in candidate.read_text(encoding='utf-8'):
                        raise Failure('An unindexed preflight file remains: ' + str(candidate))
            return
        path = Path(NOTES_ROOT) / node['path']
        require(path.parent.resolve() == (Path(NOTES_ROOT) / 'captures').resolve() and not path.is_symlink(), 'Probe path escapes the capture directory')
        body = path.read_text(encoding='utf-8')
        match = re.search(r'^capture_id: ([a-f0-9-]{36})$', body, re.M)
        require(bool(match), 'Probe file lacks a canonical capture identity')
        capture_id = match.group(1)
        if record.get('capture_id'):
            require(record['capture_id'] == capture_id, 'Probe capture identity changed; refusing deletion')
        result = self.local_json('/preflight/cleanup', {'index':node['id'], 'capture_id':capture_id, 'probe_id':probe_id})
        require(result.get('removed') is True and result.get('receipt',{}).get('status') == 'completed', 'Cleanup returned no real deletion receipt')
        after = self.get_graph()
        require(not path.exists() and all(n['path'] != node['path'] for n in after['nodes']), 'The probe still exists on disk or in the served index after cleanup')

    def check_remember(self):
        from build import NOTES_ROOT
        health = self.local_json('/health')
        require(health.get('capabilities',{}).get('preflight_cleanup') is True, 'Running server lacks scoped preflight cleanup; restart it before creating a probe')
        if self.pending_path.exists():
            previous = json.loads(self.pending_path.read_text())
            self.cleanup_probe(previous)
            self.pending_path.unlink()
        before = self.get_graph()
        page = self.ensure_page()
        probe_id = str(uuid.uuid4())
        word = 'lantern' + uuid.uuid4().hex[:12]
        text = f'Temporary preflight probe {probe_id}: the verification word is {word}. Disposable live check; not user memory.'
        record = {'base':self.base,'probe_id':probe_id,'capture_id':None}
        self.save_pending(record)  # Survives a crash before the response arrives.
        failure = None
        capture = None
        errors_before = len(self.page_errors)
        try:
            nonce = str(uuid.uuid4())
            page.evaluate('(nonce) => {window.__preflightPageNonce=nonce;}', nonce)
            page.locator('#question').fill('remember that ' + text)
            with page.expect_response(lambda response: urlsplit(response.url).path == '/remember' and response.request.method == 'POST', timeout=45000) as pending:
                page.locator('#ask-button').click()
            response = pending.value
            record['capture_id'] = response.request.headers.get('idempotency-key')
            self.save_pending(record)
            require(response.status in (200,201), f'/remember: HTTP {response.status}')
            capture = response.json()
            index = capture.get('index')
            require(type(index) is int and capture.get('node',{}).get('id') == index and capture.get('receipt',{}).get('status') == 'completed', '/remember returned no indexed capture and execution receipt')
            require(capture.get('receipt',{}).get('outcome') == 'done', '/remember receipt did not publish outcome=done')
            path = Path(NOTES_ROOT) / capture['node']['path']
            require(path.parent.resolve() == (Path(NOTES_ROOT) / 'captures').resolve() and not path.is_symlink(), 'Capture receipt points outside captures')
            body = path.read_text(encoding='utf-8')
            require(text in body and datetime.now().astimezone().date().isoformat() in body, '/remember did not write the real dated markdown content')
            served = self.get_graph()
            require(served['nodes'][index] == capture['node'], 'The markdown exists but the running graph did not index it')
            self.wait_browser('!galaxy.busy', timeout=15)
            state = page.evaluate('''() => ({selected:galaxy.selectedId,birth:galaxy.lastBirth,nodes:galaxy.nodes.length,sprites:galaxy.sprites.size,nonce:window.__preflightPageNonce})''')
            require(state['nonce'] == nonce and state['selected'] == index and state['birth'] and state['birth']['id'] == index and state['sprites'] == state['nodes'], 'The real typed remember route did not produce/select a live star without reloading')
            answer = self.ask_ui(f'For temporary preflight probe {probe_id}, what is its verification word?')
            require(index in answer['nodes'] and word.casefold() in answer['answer'].casefold(), 'The very next /chat could not retrieve the freshly written fact/source')
            require(len(self.page_errors) == errors_before, 'Live capture raised a browser error: ' + '; '.join(self.page_errors[errors_before:]))
        except Exception as error:
            failure = error
        finally:
            try:
                self.cleanup_probe(record)
                current = json.loads(self.pending_path.read_text())
                require(current.get('probe_id') == probe_id, 'Pending cleanup journal changed unexpectedly')
                self.pending_path.unlink()
            except Exception as error:
                failure = Failure(f'{self.safe(failure) + "; " if failure else ""}CLEANUP FAILED: {self.safe(error)}; ownership journal retained at {self.pending_path}')
        if failure:
            raise failure
        after = self.get_graph()
        require(after == before, 'Probe removal did not preserve all original graph nodes, ids and links')
        return f'Real markdown, live star and immediate model source #{capture["index"]}; test file and index entry removed'

    def check_files(self):
        health = self.local_json('/health')
        # Check every source the process reports, not a hand-picked subset:
        # a stale server used to pass while edited helper modules (web_runner,
        # ocr_backends, plan_files, evolution, ...) were silently ignored.
        sources = health.get('sources') or {}
        require(bool(sources), 'The running server reported no source fingerprints')
        for name, digest in sources.items():
            path = ROOT / name
            if not path.is_file():
                raise Failure(f'STALE RUNNING BACKEND: {name} is reported by /health but missing on disk')
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            require(digest == actual,
                    f'STALE RUNNING BACKEND: {name} differs from disk; restart server.py')
        if self.config_hash is not None:
            require(hashlib.sha256(resolve_config_path(ROOT).read_bytes()).hexdigest() == self.config_hash, 'config.json changed during preflight; rerun the checks')
        page = self.ensure_page()
        self.responses.clear()
        # Static assets carry ETag headers, so a plain reload answers 304 and
        # Playwright cannot hand back a body to compare. Clear the HTTP cache
        # first so this check always proves real bytes, not a cache hit.
        try:
            cdp = page.context.new_cdp_session(page)
            cdp.send('Network.clearBrowserCache')
            cdp.detach()
        except Exception:
            pass
        page.reload(wait_until='networkidle', timeout=90000)
        self.wait_browser('window.galaxy && (galaxy.ready || galaxy.error)',timeout=30)
        required = {'/index.html'}
        for asset in PageAssets(page.content()).urls:
            parsed = urlsplit(urljoin(self.base + '/', asset))
            if f'{parsed.scheme}://{parsed.netloc}' == self.base:
                required.add(parsed.path)
        checked = set()
        for response in self.responses:
            parsed = urlsplit(response.url)
            if f'{parsed.scheme}://{parsed.netloc}' != self.base or response.request.resource_type not in ('document','script','stylesheet','image','font'):
                continue
            relative = 'index.html' if parsed.path == '/' else unquote(parsed.path).lstrip('/')
            disk = ROOT / 'viewer' / relative
            require(disk.resolve().is_relative_to((ROOT/'viewer').resolve()) and not disk.is_symlink() and disk.is_file(), f'Served browser asset has no real matching disk file: {parsed.path}')
            served = response.body()
            require(response.status == 200 and served == disk.read_bytes(), f'STALE SERVED FILE: {relative}; browser bytes differ from disk')
            require(not self.key or self.key.encode() not in served, 'SECURITY FAILURE: a served asset contains the private API key')
            checked.add('/' + relative)
        require(required <= checked, 'Browser did not receive all local assets: ' + ', '.join(sorted(required - checked)))
        # The generated public asset must also agree with the editable persona source.
        tree = ast.parse((ROOT/'server.py').read_text())
        greeting = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target,ast.Name) and target.id == 'BOOT_GREETING' for target in node.targets))
        require(page.evaluate('window.GALAXY_PERSONA?.greeting') == greeting, 'Generated persona.js is stale relative to the persona block')
        require(not self.page_errors, 'Live browser script errors: ' + '; '.join(self.page_errors))
        return (f'{len(checked)} actual browser assets byte-identical; '
                f'{len(sources)} running backend fingerprints match disk')

    def check_config(self):
        for path in ('/config.json','/viewer/config.json','/../config.json','/%2e%2e%2fconfig.json','/%252e%252e%252fconfig.json'):
            status, _, raw = self.local(path)
            require(status in (403,404), f'SECURITY FAILURE — PRIVATE CONFIG REACHABLE: {path} returned HTTP {status}')
            require(not self.key or self.key.encode() not in raw, f'SECURITY FAILURE — API KEY LEAKED through {path}')
        return 'Root config and traversal paths denied (403/404); no key exposed'

    def check_mute(self):
        page = self.ensure_page()
        require('mute=1' in urlsplit(page.url).query.split('&'), 'The live test tab is not muted by URL')
        page.locator('#note-search').click()  # Trusted click unlocks speech; activation cannot mask a missing mute guard.
        state = page.evaluate('''() => {const refused=galaxy.voice.speak('This is a muted live preflight check.');return {refused,speaking:galaxy.voice.speaking,nativeSpeaking:speechSynthesis.speaking,nativePending:speechSynthesis.pending,status:document.getElementById('voice-status').textContent};}''')
        require(state['refused'] is False and not state['speaking'] and not state['nativeSpeaking'] and not state['nativePending'] and 'Muted by URL' in state['status'], f'The real speak function did not refuse mute=1: {state}')
        return 'After a trusted click, real speak() returned false; native speech queue remains empty'

    def check_voice(self):
        page = self.ensure_page()
        state = page.evaluate('''() => ({
            output: !!document.getElementById('voice-output'),
            options: document.getElementById('voice-output')?.options.length || 0,
            hasEdge: [...(document.getElementById('voice-output')?.options || [])].some(option => option.value.startsWith('edge:')),
            meter: !!document.getElementById('mic-level'),
            meterHidden: document.getElementById('mic-level')?.hidden === true,
            ptt: !!document.querySelector('.ptt-hint') && /Ctrl/.test(document.querySelector('.ptt-hint').textContent),
            picker: typeof galaxy.voice.chooseVoice === 'function',
            micPressed: document.getElementById('mic-button').getAttribute('aria-pressed')
        })''')
        require(state['output'] and state['options'] >= 1, f"Output voice picker is missing options: {state}")
        require(state['hasEdge'], f"The Edge voice options are missing: {state}")
        require(state['meter'] and state['meterHidden'], f"Microphone level meter is not in its idle state: {state}")
        require(state['ptt'], 'The push-to-talk hint is missing')
        require(state['picker'], 'The live voice controller has no chooseVoice function')
        require(state['micPressed'] == 'false', 'The voice check began with the microphone already armed')
        # Electron has no Google speech backend, so the microphone only works through
        # the local transcriber. Prove the whole path: Edge TTS makes a Polish clip,
        # /voice/transcribe runs ffmpeg + whisper.cpp and must return the words.
        live = self.local_json('/voice/status')
        require(live.get('available') is True,
                'The offline transcriber is not installed; run scripts/install-stt.sh')
        status, headers, audio = self.local('/tts', {'text': 'Jaki jest mój plan treningowy?',
                                                     'voice': 'pl-PL-MarekNeural'})
        require(status == 200 and headers.get('Content-Type') == 'audio/mpeg',
                f"/tts for the transcription probe: HTTP {status}")
        status, _, raw = self.local_bytes('/voice/transcribe', audio, 'audio/mpeg')
        require(status == 200, f'/voice/transcribe: HTTP {status}')
        try:
            spoken = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Failure('/voice/transcribe did not return JSON') from None
        text = str(spoken.get('text') or '').lower()
        require(spoken.get('ok') is True and 'plan' in text,
                f'Offline transcription returned no usable Polish text: {spoken}')
        return (f"Edge voice options, idle input meter, push-to-talk and offline transcription are live "
                f"({live.get('engine')}, {spoken.get('seconds')} s for a spoken Polish question)")

    def check_tts(self):
        live = self.local_json('/tts/status')
        require(live.get('engine') == 'edge-tts' and live.get('available') is True,
                f"Edge TTS is not available: {live}")
        voices = live.get('voices') or []
        require(live.get('default_voice') in [voice.get('id') for voice in voices],
                'The Edge TTS status is missing its default voice')
        encoded = json.dumps(live, ensure_ascii=False)
        require('/home/' not in encoded and 'sk-or-' not in encoded,
                'The Edge TTS status exposed a local path or credential')
        status, headers, audio = self.local('/tts', {
            'text': 'The atlas is ready, sir.',
            'voice': live['default_voice'],
        })
        require(status == 200, f'/tts: HTTP {status}')
        require(headers.get('Content-Type') == 'audio/mpeg', f"/tts returned {headers.get('Content-Type')}")
        require(len(audio) > 2000 and audio[:1] == b'\xff' and (audio[1] & 0xE0) == 0xE0,
                'Edge TTS did not return a plausible MPEG audio frame')
        return f"Edge TTS synthesized {len(audio)} bytes of MPEG audio with {live['default_voice']}"

    def check_agent(self):
        live = self.local_json('/agent/status')
        require(live.get('available') is True, f'The browser agent is not available: {live}')
        job = live.get('job')
        require(job is None or (isinstance(job, dict) and job.get('status') not in ('queued', 'running', 'awaiting_approval')),
                'The agent lane started with a stale active job')
        require(set(live.get('modes') or []) == {'safe', 'standard', 'full'},
                'The operator mode registry is incomplete')
        require((live.get('features') or {}).get('shell') is True
                and (live.get('features') or {}).get('files') is True,
                'The operator did not expose shell/files')
        require((live.get('features') or {}).get('pty') is True
                and (live.get('features') or {}).get('tabs') is True
                and (live.get('features') or {}).get('ocr') is True
                and (live.get('features') or {}).get('model_fallback') is True
                and (live.get('features') or {}).get('selfmod') is True
                and (live.get('features') or {}).get('skill_forge') is True
                and (live.get('features') or {}).get('self_heal') is True
                and (live.get('features') or {}).get('subagents') is True,
                'The operator did not expose the self-modification or subagent upgrades')
        schedules = self.local_json('/agent/schedules')
        require(isinstance(schedules.get('schedules'), list),
                'The operator schedule API did not return a list')
        encoded = json.dumps(live, ensure_ascii=False)
        require('/home/' not in encoded and 'sk-or-' not in encoded,
                'The agent status exposed a local path or credential')
        import browser_agent
        names = {tool['name'] for tool in browser_agent.TOOLS}
        require({'terminal', 'read_file', 'write_file', 'restore_file', 'ocr_image', 'desktop', 'secret'}.issubset(names),
                f'The operator tool registry is incomplete: {sorted(names)}')
        require('delegate' in names, 'The operator does not expose the delegation tool')
        import subagent_manager
        require({'write_file', 'terminal', 'secret', 'memory', 'mcp', 'delegate'}.isdisjoint(subagent_manager.SUBAGENT_TOOLS),
                'A delegated child allowlist includes a dangerous tool')
        probe = browser_agent.AgentService.probe(self.base + '/')
        require(probe.get('title') == 'Jarvis — Knowledge Console',
                f'The real agent browser did not read the local viewer: {probe}')
        require(probe.get('elements', 0) > 10 and probe.get('text') is True,
                f'The real agent browser returned no usable page state: {probe}')
        return f"operator ready; {len(browser_agent.TOOLS)} tools; headless page '{probe['title']}' with {probe['elements']} elements"

    def check_p1(self):
        live = self.local_json('/agent/status')
        features = live.get('features') or {}
        require(all(features.get(name) is True for name in
                    ('memory', 'session_search', 'skills', 'scheduler_v2', 'mcp', 'web_research')),
                f'The P1 feature flags are incomplete: {features}')
        memory = self.local_json('/memory')
        require(memory.get('ok') is True and isinstance(memory.get('memories'), list),
                'The personal memory API did not return a list')
        stats = memory.get('stats')
        require(isinstance(stats, dict) and isinstance(stats.get('total'), int),
                'The personal memory API did not report its size')
        require(isinstance(memory.get('models'), list), 'The personal memory API returned no mental models')
        encoded = json.dumps(memory, ensure_ascii=False)
        require('/home/' not in encoded, 'The memory API leaked a local path')
        sessions = self.local_json('/sessions')
        require(sessions.get('ok') is True and isinstance(sessions.get('sessions'), list),
                'The session archive API did not return a list')
        hits = self.local_json('/sessions/search?q=jarvis')
        require(hits.get('ok') is True and isinstance(hits.get('hits'), list),
                'The session search API did not return a list')
        skills = self.local_json('/skills')
        require(skills.get('ok') is True and isinstance(skills.get('skills'), list) and skills['skills'],
                'The skill library returned no skills')
        self.local_json('/skills/view?name=operator-safe-file-writes')
        mcp = self.local_json('/mcp')
        require(mcp.get('ok') is True and isinstance(mcp.get('servers'), list),
                'The MCP status API did not return a list')
        status, _, _ = self.local('/research')
        require(status == 400, f'Empty research query returned HTTP {status}, expected 400')
        page = self.open_studio('skills')
        try:
            # The list arrives over HTTP; wait for a rendered row instead of a
            # fixed delay, otherwise a slow /skills call looks like an empty tab.
            page.locator('#skill-list button').first.wait_for(state='visible', timeout=15000)
            require(page.locator('#skill-list button').count() >= 1,
                    'The Studio skill panel rendered no skills')
        finally:
            self.close_studio()
        import mcp_client
        import memory_store
        import session_store
        import skills_store
        import web_research
        require(callable(memory_store.MemoryStore) and callable(session_store.SessionStore)
                and callable(skills_store.SkillStore) and callable(mcp_client.MCPManager)
                and callable(web_research.search),
                'A P1 module is not importable')
        return (f"memory ({stats['total']} facts, semantic "
                f"{'on' if stats.get('semantic') else 'off'}), durable sessions, "
                f"{len(skills['skills'])} skills and "
                f"{len(mcp.get('servers') or [])} configured MCP servers are live")

    def check_p2(self):
        system = self.local_json('/system')
        require(isinstance(system.get('memory'), dict) and system['memory'].get('total', 0) > 0,
                'The system monitor returned no memory data')
        briefing = self.local_json('/briefing')
        require(briefing.get('ok') is True and 'Daily briefing' in briefing.get('heading', ''),
                'The briefing endpoint returned no local briefing')
        documents = self.local_json('/documents')
        require(isinstance(documents.get('documents'), list), 'The document library did not return a list')
        status, _, _ = self.local('/clipboard')
        require(status in (200, 409), f'Clipboard returned HTTP {status}')
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary, 'duplicate-a.txt').write_text('same', encoding='utf-8')
            Path(temporary, 'duplicate-b.txt').write_text('same', encoding='utf-8')
            scan = self.local_json('/organizer?root=' + quote(temporary))
            require(scan.get('files') == 2 and len(scan.get('duplicates') or []) == 1,
                    'The organizer did not find the live duplicate group')
        page = self.open_studio('system')
        try:
            page.locator('#system-metrics .studio-metric').first.wait_for(state='visible', timeout=15000)
            require(page.locator('#system-metrics .studio-metric').count() >= 3,
                    'The Studio system tab rendered no live metrics')
        finally:
            self.close_studio()
        page.locator('#capability-toggle').click()
        page.locator('#capability-overlay').wait_for(state='visible', timeout=10000)
        try:
            page.locator('.capability-item').first.wait_for(state='visible', timeout=20000)
            require(page.locator('.capability-item').count() >= 10,
                    'The capability map rendered too few live cards')
        finally:
            page.locator('#capability-close').click()
        import app_identity
        import briefing
        import clipboard
        import documents
        import file_organizer
        import system_monitor
        require(callable(system_monitor.snapshot) and callable(file_organizer.scan)
                and callable(documents.generate) and callable(briefing.build)
                and callable(app_identity.find) and callable(clipboard.read),
                'A P2 module is not importable')
        return f"system {system.get('memory', {}).get('percent', '?')}% memory; briefing, documents, organizer, Studio and capability map live"

    def check_p3(self):
        services = self.local_json('/services')
        require(services.get('available') is True, 'The systemd user supervisor is unavailable')
        require(services.get('active') == 'active', f"The Jarvis service is {services.get('active', 'unknown')}")
        suggestions = self.local_json('/memory/suggestions')
        require(suggestions.get('ok') is True and isinstance(suggestions.get('suggestions'), list),
                'The memory suggestion API is malformed')
        queue = self.local_json('/agent/queue')
        require(isinstance(queue.get('queue'), list), 'The Operator queue API is malformed')
        docs = self.local_json('/documents')
        require(isinstance(docs.get('templates'), list) and docs['templates'],
                'The document template catalogue is empty')
        capabilities = self.local_json('/capabilities')
        require(any(item.get('id') == 'operator_delegation' for item in capabilities.get('capabilities', [])),
                'The capability map has no operator delegation entry')
        page = self.open_studio('selfmod')
        try:
            page.locator('#studio-selfmod').wait_for(state='visible', timeout=10000)
            require(page.locator('#studio-selfmod').is_visible(), 'The Studio Selfmod tab is not visible')
            require(page.locator('#selfmod-proposals').count() == 1, 'The Selfmod proposal list is missing')
        finally:
            self.close_studio()
        import router
        import service_control
        route = router.classify('/operator echo hello')
        require(route.get('action') == 'operator' and route.get('task') == 'echo hello',
                'The request router does not preserve an explicit Operator task')
        require(callable(service_control.install) and callable(service_control.status),
                'The service controller is not importable')
        return f"service {services.get('active')}; router, suggestion memory, queue and document templates live"

    def check_selfmod(self):
        live = self.local_json('/self/status')
        require(live.get('ok') is True, 'The self-modification status did not return ok')
        require(isinstance(live.get('skills'), list) and isinstance(live.get('rules'), list)
                and isinstance(live.get('patches'), list) and isinstance(live.get('proposals'), list),
                'The self-modification status is malformed')
        status, _, _ = self.local('/self/run', {'name': 'missing-skill', 'arguments': {}})
        require(status == 400, f'An unconfirmed skill run returned HTTP {status}')
        status, _, _ = self.local('/self/rules', {'action': 'add', 'text': 'preflight probe'})
        require(status == 400, f'An unconfirmed rule change returned HTTP {status}')
        status, _, _ = self.local('/self/forge/apply', {'proposal_id': 'missing', 'token': 'wrong'})
        require(status == 400, f'An invalid forge proposal returned HTTP {status}')
        import self_modify
        require(self_modify.policy_for(self_modify.ROOT / 'browser_agent.py') == 'guarded',
                'browser_agent.py is not guarded for Auto-Heal')
        require(self_modify.policy_for(self_modify.ROOT / 'config.json') == 'blocked',
                'config.json is not blocked for Auto-Heal')
        valid, _ = self_modify.SkillCrucible.validate_ast(
            "import subprocess\ndef execute(**kwargs):\n    return subprocess.run(['id'])\n")
        require(not valid, 'The skill AST policy accepted a subprocess import')
        valid, _ = self_modify.SkillCrucible.validate_ast(
            "import pathlib\ndef execute(**kwargs):\n    return pathlib.Path('.').name\n")
        require(valid, 'The skill AST policy rejected pathlib')
        for bypass in (
            "def execute(**kwargs):\n    import os as o\n    return o.system('id')\n",
            "def execute(**kwargs):\n    from os import system\n    return system('id')\n",
            "def execute(**kwargs):\n    import sys\n    return sys.modules['subprocess'].check_output(['id'])\n",
        ):
            valid, _ = self_modify.SkillCrucible.validate_ast(bypass)
            require(not valid, 'The skill AST policy accepted an alias/import bypass')
        forged = self_modify.SkillCrucible.test(
            'import json\nprint("__JARVIS_RESULT_" + "x" + "__" + json.dumps('
            '{"ok": True, "results": [{"index": 0, "success": True}]}))\n'
            'raise SystemExit(0)\ndef execute(**kwargs):\n    return "wrong"\n',
            [{"input": {}, "expect": "expected"}])
        require(not forged.get('ok'), 'The Crucible accepted a forged result marker')
        self.local_json('/self/skills')
        self.local_json('/self/rules')
        self.local_json('/self/patches')
        modules = self.local_json('/modules')
        require(isinstance(modules.get('modules'), list), 'The module registry did not return a list')
        undo = self.local_json('/undo')
        require(undo.get('ok') is True and isinstance(undo.get('entries'), list), 'The undo status is malformed')
        import operator_verify
        import tool_registry
        require(callable(tool_registry.ToolRegistry) and callable(operator_verify.verify), 'The modular/verification lane is not importable')
        return f"self-modification ready; {len(live.get('skills') or [])} generated skills; operators can forge, heal and learn"

    def check_teardown(self):
        status, _, raw = self.local('/teardown/diag')
        require(status == 200, f'/teardown/diag returned HTTP {status}')
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Failure('/teardown/diag did not return JSON') from None
        problems = data.get('problems') if isinstance(data, dict) else None
        require(data.get('ready') is True, 'Teardown bay is not ready: ' + ('; '.join(problems or ['no detail'])))
        rea = data.get('rea') or {}
        pinned, installed = rea.get('pinned'), rea.get('installed')
        require(isinstance(pinned, str) and re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?', pinned),
                'REA is not pinned to an exact version')
        require(pinned == installed, f'REA pinned {pinned} but installed {installed}')
        require(rea.get('repository_official') is True, 'REA package is not from github.com/morluto/rea')
        node = data.get('node') or {}
        require(node.get('supported') is True and node.get('version'), 'REA requires a supported Node.js 22.19+/24.11+')
        chrome = data.get('chrome') or {}
        require(chrome.get('found') is True, 'Chrome was not found for browser teardown work')
        return (f"ready; REA {pinned} pinned+installed; Node {node['version']}; "
                f"Chrome {chrome.get('kind') or 'found'}")

    @staticmethod
    def _port_open(port):
        sock = socket.socket()
        try:
            return sock.connect_ex(('127.0.0.1', port)) == 0
        finally:
            sock.close()

    @staticmethod
    def _pids_referencing(path):
        needle = str(path)
        pids = []
        for entry in Path('/proc').iterdir() if Path('/proc').is_dir() else []:
            if not entry.name.isdigit():
                continue
            try:
                argv = (entry / 'cmdline').read_bytes().split(b'\0')
            except OSError:
                continue
            if any(needle.encode() in arg for arg in argv):
                pids.append(int(entry.name))
        return pids

    def check_browser(self):
        status, _, raw = self.local('/teardown/browser', {
            'url': 'https://en.wikipedia.org/wiki/WebSocket',
            'headless': True,
            'scroll': True,
        }, timeout=120)
        require(status == 200, f'/teardown/browser returned HTTP {status}: {raw[:300]!r}')
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Failure('/teardown/browser did not return JSON') from None
        require(data.get('ok') is True, 'The ephemeral browser did not report success')
        require(data.get('headless') is True, 'The preflight browser was not headless')
        require(data.get('ready_state') == 'complete', f"readyState was {data.get('ready_state')!r}, not complete")
        require(isinstance(data.get('load_seconds'), (int, float)) and data['load_seconds'] >= 0,
                'The browser did not report load seconds')
        require(bool(data.get('title')), 'The browser reported an empty page title')
        require(bool(data.get('url')) and 'wikipedia.org' in data['url'], 'The browser landed on the wrong URL')
        require(data.get('window_size') == [1280, 820], 'The browser did not use a 1280x820 window')
        require(data.get('scrolled') is True and data.get('scroll_y_after', 0) > data.get('scroll_y_before', 0),
                'The wheel event did not scroll the page')
        cleanup = data.get('cleanup') or {}
        require(cleanup.get('profile_removed') is True, 'The browser profile was not removed')
        require(cleanup.get('port_released') is True, 'CDP port 9333 was not released')
        require(not cleanup.get('lingering_pids'), f"Chrome still references the profile: {cleanup.get('lingering_pids')}")
        require(not cleanup.get('errors'), 'Browser cleanup reported: ' + '; '.join(cleanup.get('errors') or []))
        profile = Path(data.get('profile') or '')
        require(str(profile) and not profile.exists(), f'Profile still exists on disk: {profile}')
        require(not self._pids_referencing(profile), f'Chrome process still references {profile}')
        require(not self._port_open(9333), 'Something is still listening on 127.0.0.1:9333')
        return (f"headless {data['title']!r}; loaded in {data['load_seconds']}s; "
                f"wheel-scrolled to {data['scroll_y_after']:.0f}; profile removed; no Chrome left")

    def check_evidence(self):
        import evidence_bay
        result = evidence_bay.capture_evidence(
            'https://www.monogrid.com/', headless=True, inspect_ms=4000, analyze_ms=1500)
        digest = result.get('digest') or {}
        require(bool(result.get('title')), 'Evidence capture returned no page title')
        require(result['rea']['inspect']['scripts'] > 0, 'REA captured no scripts')
        require(len(digest.get('routes') or []) > 0, 'REA found no routes')
        require(len(digest.get('scripts') or []) > 0, 'REA found no scripts with sizes')
        require(len(digest.get('code_signals') or []) >= 3, 'No shader/uniform code signals were extracted')
        require(any(item.get('name') == 'Three.js' for item in digest.get('stack') or []),
                'The stack fingerprint did not identify the 3D engine')
        assets = digest.get('asset_totals') or {}
        require(assets.get('resources', 0) > 10, 'The Jarvis asset log is empty')
        screenshot = Path(result['rea']['screenshot']['path'])
        require(screenshot.is_file() and screenshot.read_bytes()[:8] == b'\x89PNG\r\n\x1a\n',
                'The decoded screenshot is not a PNG')
        cleanup = result.get('cleanup') or {}
        require(bool(cleanup.get('ok')) and cleanup.get('profile_removed') is True
                and cleanup.get('port_released') is True and not cleanup.get('lingering_pids'),
                'Evidence browser cleanup did not prove itself')
        profile = Path(result.get('profile') or '')
        require(str(profile) and not profile.exists(), 'Evidence profile still exists')
        require(not self._pids_referencing(profile), 'Chrome still references the evidence profile')
        require(not self._port_open(9333), 'Port 9333 is still open after evidence capture')
        require('[REA]' in result.get('digest_text', '') and '[Jarvis]' in result.get('digest_text', ''),
                'Evidence digest lost its attribution labels')
        return (f"{len(digest.get('routes') or [])} routes; {len(digest.get('code_signals') or [])} code signals; "
                f"{assets.get('resources')} assets / {assets.get('known_bytes', 0) / (1024 * 1024):.2f} MB; "
                f"PNG {result['rea']['screenshot'].get('png_width')}x{result['rea']['screenshot'].get('png_height')}; "
                f"no Chrome left")

    def check_teardown_note(self):
        import tempfile

        from build import make_graph, write_graph
        from server import Application
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'app'
            notes = Path(tmp) / 'vault'
            (root / 'viewer').mkdir(parents=True)
            notes.mkdir()
            (notes / 'seed.md').write_text('# Seed\n\nSeed note.\n')
            write_graph(make_graph(notes), root / 'viewer/graph-data.js')
            app = Application(root, notes)
            result = app.total_recall_index([
                {'path': 'NOTES/concepts/REA.md', 'content': '# REA\n\n## Teardowns\n\n- [[site-2026-10-20]]\n', 'related': 0},
                {'path': 'NOTES/captures/teardowns/site-2026-10-20.md', 'content': '# Teardown\n\n[[REA]]\n', 'related': 'REA'},
            ])
            births = result.get('births') or []
            require([birth['node']['label'] for birth in births] == ['REA', 'site-2026-10-20'],
                    'The concept and teardown were not born in REA-first order')
            require([birth['node']['id'] for birth in births] == [1, 2],
                    'The teardown births did not receive stable positional ids')
            require(births[1]['related'] == 1, 'The teardown birth is not anchored to the REA concept')
            require('[[REA]]' in (notes / 'NOTES/captures/teardowns/site-2026-10-20.md').read_text(),
                    'The teardown note does not link to the REA concept')
            require(len(app.load_graph()['nodes']) == 3, 'The teardown index did not persist')
        return 'REA concept born first, teardown second, linked and indexed with stable ids'

    def _make_panel_fixture(self):
        """Use a disposable teardown note so preflight never needs a user teardown."""
        import base64

        from build import NOTES_ROOT
        directory = Path(NOTES_ROOT) / 'NOTES/captures/teardowns'
        assets = directory / 'assets'
        assets.mkdir(parents=True, exist_ok=True)
        date = datetime.now().date().isoformat()
        name = f'preflight-panel-{date}'
        note = directory / f'{name}.md'
        image = assets / f'{name}.png'
        png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=')
        image.write_bytes(png)
        note.write_text(
            f'---\nsnapshot: "assets/{name}.png"\n---\n'
            f'# Teardown · preflight.local — {date}\n\n'
            '**Verdict:** Disposable preflight card fixture.\n\n'
            '## The answer\nPreflight fixture.\n\n'
            '## The stack\n- Three.js r165 — fixture.\n- GSAP 3.12.5 — fixture.\n\n'
            '## How the effect works\n1. Fixture.\n\n'
            '## What it loads\n- [Jarvis] 7 resource entries, 1.00 MB reported size, 0 unknown.\n'
            '- REA: 3 routes.\n\n'
            '## Rebuild it\n1. Fixture.\n\n'
            "## What the evidence can't show\nFixture.\n\n"
            f'![Teardown snapshot](assets/{name}.png)\n',
            encoding='utf-8')
        self.panel_fixture = (note, image)
        return name

    def _cleanup_panel_fixture(self):
        if not self.panel_fixture:
            return
        for path in self.panel_fixture:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        self.panel_fixture = None

    def check_teardown_panel(self):
        self._make_panel_fixture()
        status, _, raw = self.local('/teardown/last')
        require(status == 200, f'/teardown/last returned HTTP {status}')
        try:
            last = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Failure('/teardown/last did not return JSON') from None
        require(last.get('ok') is True and isinstance(last.get('markdown'), str)
                and bool(last.get('markdown').strip()), 'The last teardown note is empty')
        require(isinstance(last.get('stack'), list) and 1 <= len(last['stack']) <= 10,
                'The last teardown did not expose a bounded stack')
        page = self.ensure_page()
        page.set_viewport_size({'width': 1440, 'height': 900})
        page.wait_for_timeout(300)
        self.wait_browser('window.galaxy && galaxy.ready', timeout=20)
        cases = [
            ('reverse engineer igloo dot inc', True, 'site', 'igloo.inc'),
            ('tear down linear.app', True, 'site', 'linear.app'),
            ('how does stripe.com do that', True, 'site', 'stripe.com'),
            ('what is example.com built with', True, 'site', 'example.com'),
            ('reverse engineer this site', True, 'site', 'this'),
            ('how does this page work', True, 'site', 'this'),
            ('tear down the old shed', False, None, None),
            ('how should I reverse engineer my pricing', False, None, None),
            ("reverse engineer Stripe's homepage", False, None, None),
            ('show me the last teardown', True, 'last', None),
            ('open the full teardown', True, 'open', None),
            ('cancel the teardown', True, 'cancel', None),
        ]
        for sentence, triggered, route, site in cases:
            result = page.evaluate('sentence => galaxy.voice.inspect(sentence)', sentence)
            require(result.get('triggered') is triggered and result.get('route') == route,
                    f'Voice route mismatch for {sentence!r}: {result}')
            if site:
                require(result.get('site') == site, f'Voice route lost the address for {sentence!r}')
        require(page.evaluate("() => galaxy.voice.inspect('close the teardown').route") == 'close',
                'The close-teardown route was not registered')
        require(page.evaluate("() => galaxy.voice.speak('Muted panel check.')") is False,
                'The live ?mute=1 tab did not refuse speech')
        require(page.evaluate('() => galaxy.showLastTeardown()') is True,
                'The card could not load the last teardown')
        page.locator('#td-result').wait_for(state='visible', timeout=20000)
        page.wait_for_timeout(500)
        state = page.evaluate('''() => {
          const panel = document.getElementById('teardown-panel');
          const p = panel.getBoundingClientRect();
          const atlas = document.getElementById('atlas-panel').getBoundingClientRect();
          const note = document.getElementById('note-panel');
          const n = note.hidden ? null : note.getBoundingClientRect();
          const dock = document.getElementById('chat-dock').getBoundingClientRect();
          return {hidden: panel.hidden, site: document.getElementById('td-site').textContent,
            fold: document.getElementById('td-fold').textContent,
            chips: [...document.querySelectorAll('.td-chip')].map(node => node.textContent),
            totals: document.getElementById('td-totals').textContent,
            img: document.getElementById('td-snapshot').getAttribute('src'),
            imgLoaded: document.getElementById('td-snapshot').complete && document.getElementById('td-snapshot').naturalWidth > 0,
            steps: document.querySelectorAll('#td-steps .td-step').length,
            readDisabled: document.getElementById('td-read').disabled,
            panel: [p.left, p.top, p.right, p.bottom],
            atlasRight: atlas.right, noteLeft: n ? n.left : null, dockTop: dock.top};
        }''')
        require(state['hidden'] is False and state['site'] == last.get('site'),
                f'The teardown card did not show the site: {state}')
        require('Taken apart' in state['fold'] and 1 <= len(state['chips']) <= 10,
                f'The folded card is missing its line or stack: {state}')
        require(bool(state['totals']) and bool(state['img']) and state['imgLoaded'],
                f'The folded card is missing totals or a loaded snapshot: {state}')
        require(state['steps'] == 8 and state['readDisabled'] is False,
                'The card did not expose eight steps and a readable note')
        require(state['panel'][0] >= state['atlasRight'] - 1,
                f'The card overlaps the atlas: {state}')
        if state['noteLeft'] is not None:
            require(state['panel'][2] <= state['noteLeft'] - 1, f'The card overlaps the note panel: {state}')
        require(state['panel'][3] <= state['dockTop'] - 1, f'The card overlaps the answer/chat dock: {state}')
        page.locator('#td-read').wait_for(state='visible', timeout=10000)
        page.locator('#td-read').click()
        try:
            page.locator('#td-reader:not([hidden])').wait_for(state='visible', timeout=15000)
            reader = page.evaluate('''() => ({title:document.getElementById('td-reader-title').textContent,
              text:document.getElementById('td-reader-body').innerText,
              images:document.querySelectorAll('#td-reader-body img').length,
              obsidian:document.getElementById('td-obsidian').getAttribute('href')})''')
            require(reader.get('title') and reader.get('images', 0) >= 1, 'The reader did not show the note and snapshot')
            require('snapshot:' not in reader.get('text', '') and 'created:' not in reader.get('text', ''),
                    'The reader leaked front-matter/file paths on screen')
            require(str(reader.get('obsidian', '')).startswith('obsidian://open?path='),
                    'The reader did not provide Open in Obsidian')
        finally:
            try:
                page.locator('#td-reader-close').click()
                page.wait_for_timeout(150)
            except Exception:
                pass
        require(page.evaluate("() => document.getElementById('td-reader').hidden") is True,
                'The reader Close button did not close it')
        return (f"12 route sentences classified; 8-step card; 10 stack chips; "
                f"{state['totals']}; snapshot loaded; reader opens and closes")

    def check_kit(self):
        status, _, raw = self.local('/teardown/diag')
        require(status == 200, f'/teardown/diag returned HTTP {status}')
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Failure('/teardown/diag did not return JSON') from None
        require(data.get('ready') is True, 'Teardown kit is not ready: ' + '; '.join(data.get('problems') or ['no detail']))
        rea = data.get('rea') or {}
        pinned, installed = rea.get('pinned'), rea.get('installed')
        require(isinstance(pinned, str) and re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?', pinned),
                'REA is not pinned to an exact version')
        require(pinned == installed, f'REA pinned {pinned} but installed {installed}')
        require(rea.get('repository_official') is True, 'REA package is not from github.com/morluto/rea')
        require((data.get('node') or {}).get('supported') is True, 'The pinned REA needs an unsupported Node.js')
        require((data.get('chrome') or {}).get('found') is True, 'Chrome is missing for the teardown kit')
        return f'ready; REA {pinned} pinned+installed; Node {(data.get("node") or {}).get("version")}; Chrome found'

    def check_offline(self):
        import teardown_offline
        result = teardown_offline.run_checks()
        require(result.get('addresses') == 5, 'The five spoken addresses did not all parse')
        require((result.get('fingerprints') or {}).get('Three.js') == '165',
                'The synthetic Three.js fingerprint was not r165')
        require((result.get('fingerprints') or {}).get('GSAP') == '3.12.5',
                'The synthetic GSAP fingerprint was not 3.12.5')
        require(result.get('digest_lines', 0) > 0, 'The synthetic digest was empty')
        return result.get('summary') or 'offline checks passed'

    def check_webbackends(self):
        import web_backends
        state = web_backends.status(probe=True)
        if not state.get('installed'):
            raise WarningVerdict('No isolated web venv; the builtin urllib reader is active')
        require(state.get('reachable'), 'The web backend venv did not answer its probe')
        engines = state.get('engines') or {}
        require(engines.get('crawl4ai') and engines.get('scrapling'),
                f'An isolated web engine is missing: {engines}')
        page = web_backends.fetch('https://example.com', 30)
        require(bool(page), 'The isolated reader returned no page for example.com')
        require(page.get('engine') == 'crawl4ai', f"Expected crawl4ai, got {page.get('engine')}")
        require('example domain' in (page.get('title') or '').lower(),
                f"Unexpected page title: {page.get('title')!r}")
        return (f"crawl4ai+scrapling ready; {len(page['text'])} chars via {page['engine']}")

    def check_context(self):
        import context_budget
        import context_compressor
        import context_state
        payload = {'ok': True, 'status': 'done', 'output': 'x' * 24000,
                   'elements': [{'index': index} for index in range(300)]}
        bounded = context_budget.compress_payload(payload, 2000, max_items=50)
        stats = context_budget.stats(json.dumps(payload), json.dumps(bounded))
        require(bounded.get('ok') is True and bounded.get('status') == 'done',
                'Tool payload compression changed a control field')
        require(len(bounded.get('elements') or []) == 51,
                'The element list was not bounded with an explicit marker')
        require(stats['ratio'] < 0.2, f"Compression kept {stats['ratio']:.0%} of the payload")
        compressor = context_compressor.ContextCompressor(
            'deepseek-flash', context_length=20000, threshold_percent=0.5,
            protect_first_n=1, protect_last_n=2, max_tokens=1000,
            state_store=context_state.NullStateStore(), state_key='',
            summary_caller=None, quiet_mode=True,
        )
        require(compressor.threshold_tokens > 0 and compressor.tail_token_budget > 0,
                'The context compressor has no usable trigger or tail budget')
        messages = [
            {'role': 'user', 'content': 'probe'},
            {'role': 'assistant', 'content': [{
                'type': 'tool_use', 'id': 'p1', 'name': 'terminal',
                'input': {'command': 'echo old'}}]},
            {'role': 'user', 'content': [{
                'type': 'tool_result', 'tool_use_id': 'p1',
                'content': 'old result ' * 2000}]},
            {'role': 'assistant', 'content': [{
                'type': 'tool_use', 'id': 'p2', 'name': 'terminal',
                'input': {'command': 'echo recent'}}]},
            {'role': 'user', 'content': [{
                'type': 'tool_result', 'tool_use_id': 'p2',
                'content': 'recent result ' * 2000}]},
        ]
        pruned, pruned_count = compressor._prune_old_tool_results(
            messages, protect_tail_count=1)
        require(pruned[1].get('content') == messages[1].get('content'),
                'The context compressor rewrote tool-call arguments')
        require(pruned_count > 0, 'The context compressor did not prune an old tool result')
        require(pruned[2].get('content')[0].get('content') != messages[2].get('content')[0].get('content'),
                'The old tool result was not replaced')
        return (f"tool payload bounded to {stats['ratio']:.0%} "
                f"({stats['tokens_saved']} tokens saved); context compressor "
                f"trigger={compressor.threshold_tokens} tail={compressor.tail_token_budget}")

    def check_checkpoints(self):
        import shutil as _shutil
        import tempfile as _tempfile

        import checkpoint_manager
        if _shutil.which('git') is None:
            raise WarningVerdict('git is not installed; file checkpoints are unavailable')
        with _tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'project'
            root.mkdir()
            (root / 'pyproject.toml').write_text('[project]\nname="checkpoint-probe"\n', encoding='utf-8')
            (root / 'note.txt').write_text('before\n', encoding='utf-8')
            (root / '.env').write_text('SECRET=do-not-capture\n', encoding='utf-8')
            (root / 'config.json').write_text('{\"api_key\": \"do-not-capture\"}\n', encoding='utf-8')
            (root / '.gitignore').write_text('!.env\n!config.json\n', encoding='utf-8')
            manager = checkpoint_manager.CheckpointManager(
                base=Path(tmp) / 'checkpoints', enabled=True,
                max_file_size_mb=20, max_snapshots=5, max_total_size_mb=50,
            )
            manager.new_turn()
            require(manager.ensure_checkpoint(root, 'preflight before write'),
                    'The checkpoint manager did not take the first snapshot')
            (root / 'note.txt').write_text('after\n', encoding='utf-8')
            manager.record_agent_write(str(root / 'note.txt'))
            manager.new_turn()
            require(manager.ensure_checkpoint(root, 'preflight after write'),
                    'The checkpoint manager did not take the second snapshot')
            checkpoints = manager.list_checkpoints(root)
            require(len(checkpoints) >= 2, f'Expected two checkpoints, got {len(checkpoints)}')
            diff = manager.diff(root, checkpoints[-1]['hash'])
            require(diff.get('success') and 'note.txt' in diff.get('diff', ''),
                    'A checkpoint diff did not show the changed note')
            restored = manager.restore(root, checkpoints[-1]['hash'], safe=True)
            require(restored.get('success'), f'Safe restore failed: {restored.get("error")}')
            require((root / 'note.txt').read_text(encoding='utf-8') == 'before\n',
                    'Safe restore did not return the agent-written file')
            require((root / '.env').is_file(), 'Checkpoint restore removed an excluded secret file')
            ok_tree, tree, _ = checkpoint_manager._run_git(
                ['ls-tree', '-r', '--name-only', checkpoints[-1]['hash']],
                manager.store, root,
            )
            require(ok_tree and '.env' not in tree and 'config.json' not in tree,
                    'Checkpoint captured a private env/config file')
            status = manager.status()
            require(status.get('project_count') == 1, 'Checkpoint status lost the project registration')
        return 'shadow git snapshot, diff, safe restore and secret exclusion are live'
    def check_ocr(self):
        from PIL import Image, ImageDraw, ImageFont

        import operator_tools as ops
        engine = ops.Ocr()
        if not engine.available():
            raise WarningVerdict('No local tesseract binary; OCR is unavailable')
        path = ROOT / 'artifacts/preflight-ocr.png'
        path.parent.mkdir(parents=True, exist_ok=True)
        image = Image.new('RGB', (560, 150), 'white')
        draw = ImageDraw.Draw(image)
        draw.text((24, 34), 'Jarvis OCR preflight 42', fill='black',
                  font=ImageFont.load_default(size=28))
        image.save(path)
        try:
            result = engine.layout(str(path))
        finally:
            try:
                path.unlink()
            except OSError:
                pass
        require(result.get('engine') == 'tesseract-layout', 'Layout OCR did not run')
        require(any('Jarvis' in line['text'] for line in result.get('lines') or []),
                f"OCR could not read the probe image: {result.get('text', '')[:80]!r}")
        state = __import__('ocr_backends').status(probe=True)
        if state.get('ready'):
            surya = 'ready'
        elif state.get('installed'):
            surya = f"unavailable ({state.get('error') or 'runner did not answer'})"
        else:
            surya = 'not installed'
        return f"layout OCR read {len(result['lines'])} line(s); surya {surya}"

    def check_planfiles(self):
        import stat as _stat
        import tempfile as _tempfile

        import plan_files
        with _tempfile.TemporaryDirectory() as tmp:
            job_id = 'preflight-plan'
            plan = plan_files.PlanFiles(job_id, root=Path(tmp))
            plan.start('preflight plan probe', ['read the page', 'report the title'])
            require(plan.status()['total'] == 2, 'The plan did not keep its phases')
            require(plan.gate()['allow'] is False, 'The gate allowed an unchecked plan')
            plan.check(0)
            plan.note('the title is in the toolbar')
            plan.log('open_url ok')
            again = plan_files.PlanFiles(job_id, root=Path(tmp))
            require(again.status()['done'] == 1, 'A restart lost the checked phase')
            require('toolbar' in again.read_all()['findings.md'], 'A restart lost the findings')
            require('open_url' in again.read_all()['progress.md'], 'A restart lost the progress log')
            again.check(1)
            require(again.gate()['allow'] is True, 'The gate still blocks a complete plan')
            mode = _stat.S_IMODE(again.path('task_plan.md').stat().st_mode)
            require(mode == 0o600, f'plan file mode is {oct(mode)}, expected 0o600')
        return '3 plan files survive a restart; gate blocks once then allows'

    def check_hardening(self):
        """The four guards taken from the Gemini patch set must be live."""
        live = self.local_json('/modules')
        rows = live.get('modules') or live.get('tools') or []
        names = {row.get('name') for row in rows if isinstance(row, dict)}
        require('archive_ops' in names,
                'The archive_ops operator module is not registered')

        import operator_tools
        home = Path.home()
        require(operator_tools.is_credential_target(home / '.ssh' / 'id_ed25519'),
                'The file reader would return a private key')
        require(operator_tools.is_credential_target(home / '.jarvis-tools' / 'secrets.json'),
                'The file reader would return the secret store')
        require(operator_tools.is_credential_target(home / '.ssh'),
                'The file reader would return a key directory')
        require(not operator_tools.is_credential_target(
                    home / '.jarvis-tools' / 'agent' / 'job-1' / 'latest.png'),
                'The Operator can no longer read its own artifacts')

        probe = 'PREFLIGHT_PROBE_9f2c41d7'
        os.environ['PREFLIGHT_PROBE_API_KEY'] = probe
        operator_tools._SECRET_ENV_VALUES = None
        try:
            cleaned = operator_tools.redact(f'token={probe}')
        finally:
            operator_tools._SECRET_ENV_VALUES = None
            os.environ.pop('PREFLIGHT_PROBE_API_KEY', None)
        require(probe not in cleaned,
                'redact() leaked the value of a secret-named environment variable')

        import browser_agent
        guard = browser_agent.RepeatGuard()
        guard.check('click_selector', {'selector': '#a'})
        guard.check('click_selector', {'selector': '#a'})
        require('LOOP_GUARD' in guard.check('click_selector', {'selector': '#a'}),
                'The repeated-call guard did not fire on the third identical call')
        return (f'{len(rows)} operator modules (archive_ops live); read guard blocks keys, '
                'secrets and the secret store; env-value redaction live; third identical '
                'call refused')

    def check_heartbeat(self):
        from operator_modules import heartbeat
        modules = self.local_json('/modules')
        require(any(row.get('name') == 'heartbeat' and row.get('enabled')
                    for row in modules.get('modules', [])), 'Heartbeat module not registered')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            require(heartbeat.check(root, [])['status'] == 'disabled', 'Heartbeat not disabled by default')
            heartbeat.configure(root, enabled=True, quiet_start=0, quiet_end=24)
            require(heartbeat.check(root, [{'id': 'probe', 'last_status': 'error', 'last_run': 1}])['status']
                    == 'quiet', 'Quiet hours did not suppress heartbeat')
        return 'registered; disabled by default; quiet hours suppress notifications'

    def check_desktop_mcp(self):
        tools = self.local_json('/mcp/tools?refresh=1').get('tools', [])
        require(any(row.get('server') == 'computer-use-linux' and row.get('name') == 'list_windows'
                    for row in tools), 'Linux desktop MCP tools not available')
        response = self.local_json('/mcp/call', {'server': 'computer-use-linux',
                                   'tool': 'list_windows', 'arguments': {}, 'confirm': True})
        result = response.get('result', {}).get('result', {})
        require(not result.get('isError'), 'Linux desktop MCP window query failed')
        content = result.get('content') or []
        require(bool(content) and content[0].get('type') == 'text', 'Desktop window result missing')
        windows = json.loads(content[0]['text'])
        require(windows.get('backend') == 'x11' and not windows.get('error'),
                'Linux desktop MCP could not query the active X11 session')
        return f"X11 desktop MCP queried {len(windows.get('windows') or [])} windows"

    def check_vision(self):
        from types import SimpleNamespace

        from PIL import Image

        import browser_agent
        from operator_modules import vision
        self.configuration()
        require(self.provider == 'deepseek', 'Vision requires DeepSeek')
        modules = self.local_json('/modules').get('modules', [])
        require(any(row.get('name') == 'vision_analyze' and row.get('enabled') for row in modules),
                'Vision Operator module not registered')
        job = object.__new__(browser_agent.AgentJob)
        job.mode = 'full'
        require('approv' in job._guard('vision_analyze', {'source': 'file'}).lower(),
                'Vision did not require approval in Full mode')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'red.png'
            Image.new('RGB', (128, 128), 'red').save(path)
            test_job = SimpleNamespace(key=self.key, model=self.model,
                                       service=SimpleNamespace(app=SimpleNamespace(read_provider=lambda: 'deepseek')))
            result = vision.vision_analyze({'source': 'file', 'path': str(path),
                                            'question': 'What colour is the image? Answer in one word.'},
                                           {'job': test_job})
            require(result.get('ok') is True and 'red' in result.get('answer', '').lower(),
                    'DeepSeek vision did not identify the synthetic red image')
        return 'approval enforced even in Full; DeepSeek identified a synthetic image'

    def check_wakeword(self):
        import subprocess
        page = self.ensure_page()
        require(page.locator('#wake-toggle').get_attribute('aria-pressed') == 'false',
                'Wake-word microphone must be off until explicitly enabled')
        status, _, audio = self.local('/tts', {'text': 'Hey Jarvis. Hey Jarvis.',
                                               'voice': 'en-GB-RyanNeural'})
        require(status == 200 and len(audio) > 2000, 'Could not synthesize wake-word probe')
        converted = subprocess.run(['ffmpeg', '-v', 'error', '-i', 'pipe:0', '-f', 's16le',
                                    '-ac', '1', '-ar', '16000', 'pipe:1'], input=audio,
                                   capture_output=True, timeout=30, check=False)
        require(converted.returncode == 0 and bool(converted.stdout), 'Could not decode wake-word probe')
        self.local_json('/voice/wake/reset', {})
        pcm = converted.stdout + bytes(32000)
        pcm += bytes((-len(pcm)) % 2560)
        detected = False
        for offset in range(0, len(pcm), 2560):
            status, _, body = self.local_bytes('/voice/wake', pcm[offset:offset + 2560],
                                                'application/octet-stream')
            require(status == 200, f'Wake-word endpoint returned HTTP {status}')
            if json.loads(body).get('detected') is True:
                detected = True
                break
        self.local_json('/voice/wake/reset', {})
        require(detected, 'The local detector did not recognise the synthetic Hey Jarvis phrase')
        return 'opt-in control off by default; local detector recognised synthetic Hey Jarvis'

    def check_personal_briefing(self):
        result = self.local_json('/briefing')
        daily = (result.get('sections') or {}).get('daily_plan') or {}
        plan = daily.get('schedule') or {}
        weather = daily.get('weather') or {}
        text = result.get('text') or ''
        require(result.get('ok') is True and plan.get('day'), 'Briefing has no day plan')
        require('active_variant' not in plan and 'today_gym' not in plan,
                'Briefing guessed the active training variant')
        require('Zapisany plan dojazdu' in text and 'Kalendarz:' in text,
                'Briefing omitted the saved commute or calendar limitation')
        if weather.get('available') and weather.get('temperature_c') is not None:
            require('Open-Meteo' in text, 'Briefing omitted its weather source')
            weather_state = 'live Open-Meteo weather'
        else:
            require('Pogoda: niedostępna' in text, 'Briefing hid a weather failure')
            weather_state = 'weather unavailable and labelled'
        page = self.open_studio('overview')
        try:
            page.locator('#briefing-text').filter(has_text='Zapisany plan dojazdu').wait_for(
                state='visible', timeout=20000)
        finally:
            self.close_studio()
        return f'saved commute and both variants in Studio; {weather_state}'

    def check_watch_pages(self):
        from operator_modules import watch_pages
        modules = self.local_json('/modules').get('modules', [])
        require(any(row.get('name') == 'watch_pages' and row.get('enabled') for row in modules),
                'Page-watch module is not registered')
        with tempfile.TemporaryDirectory() as tmp:
            context = {'state_root': Path(tmp)}
            created = watch_pages.watch_pages({'action': 'create', 'url': 'https://example.com/',
                        'conditions': [{'type': 'page_change'}]}, context)
            require(created.get('ok') and created.get('baseline'), 'Live baseline fetch failed')
            watch_id = created['watch']['id']
            checked = watch_pages.watch_pages({'action': 'check', 'id': watch_id}, context)
            require(checked.get('ok') and not checked.get('events'), 'Unchanged live page generated an event')
            require(watch_pages.watch_pages({'action': 'remove', 'id': watch_id}, context).get('ok'),
                    'Could not remove preflight watch')
        return 'real public page baseline/check/remove; no notification or permanent watch'

    def check_job_control(self):
        """Real routing plus a stub service: the lane must never start a job."""
        from types import SimpleNamespace

        import router
        from server import Handler
        cases = {'co robisz?': 'status', 'co jest w kolejce': 'queue', 'zatrzymaj to zadanie': 'stop'}
        for message, control in cases.items():
            route = router.classify(message)
            require(route.get('action') == 'job_control' and route.get('control') == control,
                    f'{message!r} was not routed to local job control')
        # A plain task must still be an Operator task, not a status shortcut.
        require(router.classify('otwórz https://example.com')['action'] == 'operator',
                'An ordinary operator task was captured by job control')

        class Stub:
            def __init__(self):
                self.job = {'id': 'probe', 'status': 'running', 'task': 'probe task', 'steps': []}
                self.queue = [{'id': 'queued-1', 'task': 'queued probe'}]
                self.start_calls = 0
                self.stopped = []
            def available(self):
                return True
            def status(self):
                return {'job': self.job, 'queue': list(self.queue)}
            def stop(self, job_id):
                self.stopped.append(job_id)
                if self.job and self.job['id'] == job_id:
                    self.job = None
                    return {'id': job_id, 'status': 'stopped'}
                self.queue = [row for row in self.queue if row['id'] != job_id]
                return {'id': job_id, 'status': 'stopped', 'removed_from_queue': True}
            def start(self, *args, **kwargs):
                self.start_calls += 1
                raise AssertionError('job control must not start a job')

        stub = Stub()
        handler = object.__new__(Handler)
        handler.server = SimpleNamespace(agent=stub)
        status = handler.job_control_answer(router.classify('co robisz?'))
        require(status.get('outcome') == 'done' and 'probe task' in status.get('answer', ''),
                'Status answer did not report the live task')
        queued = handler.job_control_answer(router.classify('co jest w kolejce'))
        require('queued probe' in queued.get('answer', ''), 'Queue answer missed the waiting task')
        stopped = handler.job_control_answer(router.classify('zatrzymaj to zadanie'))
        require(stub.stopped == ['probe'], 'Stop did not target the active job')
        require(stopped.get('outcome') == 'done' and stub.job is None,
                'Stop was not confirmed after re-reading the service')
        require(stub.start_calls == 0, 'The job-control lane started an Operator task')
        # A stop that does not take effect must never be reported as done.
        stuck = Stub()
        stuck.stop = lambda job_id: {'id': job_id, 'status': 'stopped'}
        stuck_handler = object.__new__(Handler)
        stuck_handler.server = SimpleNamespace(agent=stuck)
        require(stuck_handler.job_control_answer(router.classify('zatrzymaj'))['outcome'] == 'unverified',
                'An unconfirmed stop was reported as done')
        return 'status/queue/stop answered from live state; no job started; unconfirmed stop stays unverified'

    def check_account(self):
        """Live IMAP status and the calendar feed, using the stored credential.

        An account is optional: with no configuration this is a warning, not a
        failure. Once configured, a broken login or feed is a real failure.
        """
        from operator_modules import calendar_agent, email_agent
        configured = email_agent.ACCOUNT_PATH.exists()
        if not configured:
            raise WarningVerdict('No personal account is configured; mail and calendar stay off')
        mail = email_agent.email_agent({'action': 'status'}, {})
        require(mail.get('ok') is True, f"IMAP status failed: {mail.get('error')}")
        account = email_agent._account()
        ics = str((account.get('calendar') or {}).get('ics_credential') or '')
        if not ics:
            raise WarningVerdict(f"Mail live ({mail.get('messages')} messages, "
                                 f"{mail.get('unseen')} unseen); calendar feed not configured")
        calendar = calendar_agent.calendar_agent({'action': 'agenda', 'days': 7}, {})
        require(calendar.get('ok') is True, f"Calendar feed failed: {calendar.get('error')}")
        return (f"IMAP live: {mail.get('messages')} messages, {mail.get('unseen')} unseen; "
                f"calendar feed live: {calendar.get('count')} event(s) in 7 days")

    def check_jev(self):
        """Jev must be honest about being off, and bounded when it is on."""
        import jev_decision
        from operator_modules import mail_triage
        status = jev_decision.status()
        require(status['endpoint'] == 'https://api.typesafe.ai/v1/systemone',
                'Jev endpoint is not the official TypeSafe host')
        require(status['credential'] == 'jev-api-key', 'Jev must read its key from the store')
        triaged = mail_triage.triage(limit=3, prefer_jev=True)
        require(triaged.get('ok'), 'Mail triage could not run')
        require(triaged.get('source') in ('jev', 'rules'), 'Mail triage reported no source')
        require(all(row.get('source') in ('jev', 'rules') and 'needs_me' in row
                    for row in triaged.get('messages') or []),
                'A triage row does not say where its decision came from')
        if not status['configured']:
            return 'Jev off: no stored key, so mail triage ran on rules only (nothing pretended)'
        probe = jev_decision.decide('Jarvis preflight probe.',
                                    {'reachable': jev_decision.noul('reachable', 'Answer yes.')},
                                    timeout=8)
        require(probe.get('ok'), 'Jev is configured but did not answer')
        require(jev_decision.answer_for(probe, 'reachable') is not None,
                'Jev answered without the reachable noul')
        return f"Jev live: {probe['model']} answered in {probe['ms']} ms; triage source={triaged['source']}"

    def check_agents(self):
        """Registry, read-only sandbox and one-time consent — without spending money.

        A real agent run costs the owner's quota, so the gate proves the boundary
        and the consent chain instead of launching Claude.
        """
        import agent_cli
        import agent_consent
        live = self.local_json('/agents')
        require(live.get('ok') is True, 'The /agents endpoint did not answer')
        rows = live.get('agents') or []
        require(len(rows) == len(agent_cli.AGENTS), 'The live agent list is incomplete')
        installed = [row for row in rows if row.get('installed')]
        require(installed, 'No agent CLI was found; install claude, opencode or hermes')
        for row in installed:
            require(row.get('version'), f"{row.get('id')} is installed but reports no version")
        # The sandbox must make everything except the agent's own folder read-only.
        rendered = ' '.join(agent_cli.sandbox_argv('claude', ['true']))
        require('--ro-bind / /' in rendered, 'The agent sandbox is not read-only across /')
        require(str(agent_cli.agent_root('claude')) in rendered,
                "The agent's own folder is not writable in the sandbox")
        require('--unshare-net' not in rendered,
                'Agents need their own API; the sandbox must not cut the network')
        # Consent: one grant, bound to one task, single use.
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp) / 'consent.json'
            original = agent_consent.STORE
            agent_consent.STORE = store
            try:
                grant = agent_consent.grant('claude', 'preflight probe')
                agent_consent.consume(grant['token'], 'claude', 'preflight probe')
                try:
                    agent_consent.consume(grant['token'], 'claude', 'preflight probe')
                except agent_consent.ConsentError:
                    pass
                else:
                    raise Failure('A consent token was reusable')
                try:
                    agent_consent.grant_spoken('claude', 'x', 'nie, poczekaj')
                except agent_consent.ConsentError:
                    pass
                else:
                    raise Failure('A negative phrase was accepted as spoken consent')
            finally:
                agent_consent.STORE = original
        return (f"{len(installed)} agent CLI(s) live; read-only sandbox; "
                f"one-time consent single-use (no paid run made)")

    def check_chrome_clean(self):
        profile_root = Path.home() / '.jarvis-tools' / 'rea' / 'profiles'
        pids = self._pids_referencing(profile_root)
        require(not pids, f'Chrome processes still reference the investigation profiles: {pids}')
        debug_pids = self._pids_with_arg('--remote-debugging-port=9333')
        require(not debug_pids, f'Chrome is still listening for investigation CDP: {debug_pids}')
        leftovers = sorted(path.name for path in profile_root.iterdir()
                            if path.name != '.browser.lock') if profile_root.is_dir() else []
        require(not leftovers, f'Investigation profile folders remain: {leftovers}')
        require(not self._port_open(9333), 'Port 9333 is still open after the teardown checks')
        return 'no investigation Chrome, profile, or CDP listener remains'

    @staticmethod
    def _pids_with_arg(needle):
        found = []
        for entry in Path('/proc').iterdir() if Path('/proc').is_dir() else []:
            if not entry.name.isdigit():
                continue
            try:
                argv = (entry / 'cmdline').read_bytes().split(b'\0')
            except OSError:
                continue
            if any(needle.encode() in arg for arg in argv):
                found.append(int(entry.name))
        return found

    def _run_check(self, label, method):
        try:
            return 'pass', '✓', self.safe(getattr(self, method)())
        except WarningVerdict as error:
            return 'warn', '!', self.safe(error)
        except Exception as error:
            message = str(error) if isinstance(error, Failure) else f'{type(error).__name__}: {self.safe(error)}'
            return 'fail', '✗', self.safe(message)

    def run(self):
        started = datetime.now(timezone.utc).isoformat()
        outcomes = {}
        # These checks touch no browser page, shared port or Operator job, so they
        # can overlap. Everything that drives a page stays strictly serial.
        parallel = [item for item in CHECKS if item[0] in PARALLEL_CHECKS]
        serial = [item for item in CHECKS if item[0] not in PARALLEL_CHECKS]
        for ident, label, method in serial:
            outcomes[ident] = self._run_check(label, method)
            status, symbol, message = outcomes[ident]
            print(f'{symbol} {label}: {message}', flush=True)
        if parallel:
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = {pool.submit(self._run_check, label, method): ident
                           for ident, label, method in parallel}
                for future in as_completed(futures):
                    ident = futures[future]
                    label = next(item[1] for item in parallel if item[0] == ident)
                    outcomes[ident] = future.result()
                    status, symbol, message = outcomes[ident]
                    print(f'{symbol} {label}: {message}', flush=True)
        for ident, label, method in CHECKS:
            status, _, message = outcomes[ident]
            self.results.append({'id': ident, 'status': status, 'message': message})
        self._cleanup_panel_fixture()
        if self.browser is not None:
            try:
                self.browser.close()
            except Exception:
                pass
        if self.playwright is not None:
            self.playwright.stop()
        counts = {status:sum(item['status']==status for item in self.results) for status in ('pass','fail','warn')}
        summary = f"{counts['pass']} pass, {counts['fail']} fail, {counts['warn']} warn"
        try:
            from build import atomic_write
            atomic_write(self.report, json.dumps({'started':started,'base_url':self.base,'model':self.safe(self.model),'checks':self.results,'summary':summary},ensure_ascii=False,indent=2).encode())
        except OSError:
            counts['warn'] += 1
            print('! Could not save the optional preflight report',flush=True)
            summary = f"{counts['pass']} pass, {counts['fail']} fail, {counts['warn']} warn"
        print(summary,flush=True)
        return 1 if counts['fail'] else 0


def main():
    if any(importlib.util.find_spec(name) is None for name in ('anthropic','playwright')):
        python = ROOT / '.venv/bin/python'
        if python.is_file() and Path(sys.prefix).resolve() != (ROOT/'.venv').resolve():
            os.execv(str(python), [str(python), str(Path(__file__).resolve()), *sys.argv[1:]])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:4700', help='Running loopback server origin')
    parser.add_argument('--timeout', type=int, default=195, help='Maximum live HTTP wait in seconds')
    parser.add_argument('--report', type=Path, default=ROOT/'artifacts/preflight.json')
    args = parser.parse_args()
    if not 10 <= args.timeout <= 600:
        parser.error('--timeout must be between 10 and 600 seconds')
    descriptor = os.open(ROOT/'.preflight.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            print('✗ Another live preflight is already running',flush=True)
            print('0 pass, 1 fail, 0 warn',flush=True)
            return 1
        return Preflight(args.url,args.timeout,args.report).run()
    except Failure as error:
        print('✗ ' + str(error),flush=True)
        print('0 pass, 1 fail, 0 warn',flush=True)
        return 1
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    raise SystemExit(main())
