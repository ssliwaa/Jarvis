#!/usr/bin/env python3
"""Remote MCP face for Jarvis: Streamable HTTP transport + OAuth 2.0.

This is the transport Google Gemini Enterprise requires for a *custom MCP
server* data store (HTTPS URL, `StreamableHTTP` only, OAuth 2.0 authorization
code flow with ``https://vertexaisearch.cloud.google.com/oauth-redirect``).
The tools themselves live in ``jarvis_mcp_server.py``; this module owns the
network face and imports that tool table, so there is still one definition of
every tool.

Run::

    .venv/bin/python jarvis_mcp_http.py --show-setup     # client id/secret, URLs
    .venv/bin/python jarvis_mcp_http.py                  # serve on 127.0.0.1:4711
    .venv/bin/python jarvis_mcp_http.py --set-passphrase # owner consent phrase

Endpoints:
  POST   /mcp                          JSON-RPC (Streamable HTTP)
  GET    /mcp                          405: no server-initiated stream
  DELETE /mcp                          204: end session
  GET    /healthz                      liveness, no auth
  GET    /.well-known/oauth-authorization-server
  GET    /.well-known/oauth-protected-resource
  GET    /authorize                    owner consent page
  POST   /authorize                    consent -> redirect with code
  POST   /token                        code / refresh exchange

Environment:
  JARVIS_MCP_HTTP_HOST      default 127.0.0.1 (put a TLS tunnel in front)
  JARVIS_MCP_HTTP_PORT      default 4711
  JARVIS_MCP_PUBLIC_URL     public https origin, e.g. https://x.trycloudflare.com
  JARVIS_MCP_HTTP_READONLY  default 1; 0 exposes note writes and the Operator
  JARVIS_MCP_HTTP_ANON      default 0; 1 allows /mcp without a token
  JARVIS_MCP_PASSPHRASE     owner consent phrase (else generated once)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jarvis_mcp_server as core

STATE_PATH = Path(os.environ.get("JARVIS_MCP_HTTP_STATE")
                  or (Path.home() / ".jarvis-tools" / "mcp-http.json"))
HOST = os.environ.get("JARVIS_MCP_HTTP_HOST") or "127.0.0.1"
PORT = int(os.environ.get("JARVIS_MCP_HTTP_PORT") or "4711")
PUBLIC_URL_ENV = (os.environ.get("JARVIS_MCP_PUBLIC_URL") or "").rstrip("/")
URL_FILE = Path(os.environ.get("JARVIS_MCP_PUBLIC_URL_FILE")
                or (Path.home() / ".jarvis-tools" / "mcp-public-url.txt"))
READONLY = (os.environ.get("JARVIS_MCP_HTTP_READONLY") or "1").strip().casefold() in core.TRUTHY
ANON = (os.environ.get("JARVIS_MCP_HTTP_ANON") or "0").strip().casefold() in core.TRUTHY
SCOPES = ("jarvis.read", "jarvis.admin")
CODE_TTL = 300
ACCESS_TTL = 8 * 3600
REFRESH_TTL = 90 * 86400
MAX_SESSIONS = 200
RATE_LIMIT = 90          # requests per window per address
RATE_WINDOW = 60.0

STATE_LOCK = threading.Lock()
SESSION_LOCK = threading.Lock()
SESSIONS: dict[str, float] = {}
CODES: dict[str, dict] = {}
ACCESS: dict[str, dict] = {}
RATE: dict[str, list] = {}


_URL_CACHE: dict[str, object] = {"value": "", "stamp": 0.0}


def log(message: str) -> None:
    core.log(message)


def public_url() -> str:
    """The current public origin.

    A quick tunnel mints a new hostname on every start, so the URL is read from
    the file the tunnel writes instead of being frozen at boot: the OAuth
    metadata Gemini reads must match the hostname it actually called.
    """
    if PUBLIC_URL_ENV:
        return PUBLIC_URL_ENV
    now = time.time()
    cached = str(_URL_CACHE.get("value") or "")
    if cached and now - float(_URL_CACHE.get("stamp") or 0.0) < 5.0:
        return cached
    value = ""
    try:
        value = URL_FILE.read_text(encoding="utf-8").strip().rstrip("/")
    except OSError:
        value = ""
    if not value.startswith("http"):
        value = f"http://{HOST}:{PORT}"
    _URL_CACHE.update(value=value, stamp=now)
    return value


def _hash(phrase: str, salt: str) -> str:
    return hashlib.sha256((salt + phrase).encode("utf-8")).hexdigest()


def load_state() -> dict:
    """Owner credentials live in one 0600 file; secrets never leave this box."""
    with STATE_LOCK:
        data = {}
        try:
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        changed = False
        if not data.get("client_id"):
            data["client_id"] = "jarvis-" + secrets.token_hex(4)
            changed = True
        if not data.get("client_secret"):
            data["client_secret"] = secrets.token_urlsafe(32)
            changed = True
        if not data.get("salt"):
            data["salt"] = secrets.token_hex(16)
            changed = True
        if not data.get("passphrase_hash"):
            phrase = os.environ.get("JARVIS_MCP_PASSPHRASE") or secrets.token_urlsafe(9)
            data["passphrase_hash"] = _hash(phrase, data["salt"])
            data["passphrase_generated"] = True
            changed = True
            print("\n=== Jarvis MCP — fraza zgody (zapisz ją, pokazujemy raz) ===",
                  file=sys.stderr)
            print(f"    {phrase}\n", file=sys.stderr)
        if not isinstance(data.get("refresh"), dict):
            data["refresh"] = {}
            changed = True
        if changed:
            save_state(data)
        return data


def save_state(data: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_name(f".{STATE_PATH.name}-{os.getpid()}.tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(STATE_PATH)


def passphrase_ok(state: dict, phrase: str) -> bool:
    if not phrase:
        return False
    return hmac.compare_digest(_hash(phrase, state["salt"]), state["passphrase_hash"])


def rate_ok(address: str) -> bool:
    now = time.time()
    with SESSION_LOCK:
        stamps = [stamp for stamp in RATE.get(address, []) if now - stamp < RATE_WINDOW]
        if len(stamps) >= RATE_LIMIT:
            RATE[address] = stamps
            return False
        stamps.append(now)
        RATE[address] = stamps
        if len(RATE) > 500:
            for key in [key for key, rows in RATE.items() if not rows]:
                RATE.pop(key, None)
        return True


def issue_access(scope: str) -> tuple[str, int]:
    token = "jmt_" + secrets.token_urlsafe(32)
    with SESSION_LOCK:
        ACCESS[token] = {"expires": time.time() + ACCESS_TTL, "scope": scope}
    return token, ACCESS_TTL


def issue_refresh(scope: str, state: dict) -> str:
    token = "jmr_" + secrets.token_urlsafe(32)
    with STATE_LOCK:
        state.setdefault("refresh", {})[token] = {"expires": time.time() + REFRESH_TTL,
                                                  "scope": scope}
        now = time.time()
        for key in [k for k, row in state["refresh"].items()
                    if float(row.get("expires") or 0) < now]:
            state["refresh"].pop(key, None)
        save_state(state)
    return token


def token_scope(header: str) -> str:
    if not header:
        return "" if not ANON else "jarvis.read"
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    token = parts[1].strip()
    now = time.time()
    with SESSION_LOCK:
        row = ACCESS.get(token)
        if row and float(row["expires"]) > now:
            return str(row["scope"])
    return ""


def _scope_guard(message, scopes: set):
    """Write/control tools need jarvis.admin, not merely the read token."""
    if not isinstance(message, dict) or message.get("method") != "tools/call":
        return None
    params = message.get("params") or {}
    tool = core.TOOLS_BY_NAME.get(str(params.get("name") or ""))
    if tool is None or tool["readOnlyHint"] or "jarvis.admin" in scopes:
        return None
    return core._success(message.get("id"), core.tool_error(
        "This token carries only jarvis.read; that tool writes or controls the "
        "machine. Re-consent with the jarvis.admin scope."))


def metadata() -> dict:
    base = public_url()
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": ["client_secret_post",
                                                  "client_secret_basic"],
        "scopes_supported": list(SCOPES),
    }


def protected_resource() -> dict:
    base = public_url()
    return {"resource": f"{base}/mcp", "authorization_servers": [base],
            "scopes_supported": list(SCOPES), "bearer_methods_supported": ["header"]}


CONSENT_PAGE = """<!DOCTYPE html>
<html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Jarvis — zgoda MCP</title>
<style>
 body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;
      color:#e8ecf6;font:15px/1.5 system-ui,sans-serif}}
 form{{background:#121a30;border:1px solid #24304f;border-radius:14px;padding:28px 30px;
      width:min(430px,92vw);box-shadow:0 18px 50px rgba(0,0,0,.45)}}
 h1{{margin:0 0 6px;font-size:19px;letter-spacing:.02em}}
 p{{margin:0 0 18px;color:#9fb0d0;font-size:13px}}
 code{{background:#0b1020;border:1px solid #24304f;border-radius:6px;padding:1px 5px;
      font-size:12px;color:#8fd0ff}}
 input[type=password]{{width:100%;box-sizing:border-box;padding:11px 12px;border-radius:9px;
      border:1px solid #2c3a5e;background:#0b1020;color:#e8ecf6;font-size:15px}}
 button{{margin-top:14px;width:100%;padding:11px;border:0;border-radius:9px;
      background:#2563eb;color:#fff;font-size:15px;font-weight:600;cursor:pointer}}
 .meta{{margin-top:16px;font-size:12px;color:#7e8fb3;word-break:break-all}}
</style></head>
<body><form method="post" action="/authorize">
 <h1>Jarvis prosi o dostęp</h1>
 <p>Klient <code>{client_id}</code> chce wywoływać narzędzia MCP Jarvisa
    w zakresie <code>{scope}</code>. Wpisz frazę zgody właściciela.</p>
 <input type="hidden" name="client_id" value="{client_id}">
 <input type="hidden" name="redirect_uri" value="{redirect_uri}">
 <input type="hidden" name="state" value="{state}">
 <input type="hidden" name="scope" value="{scope}">
 <input type="hidden" name="code_challenge" value="{challenge}">
 <input type="hidden" name="code_challenge_method" value="{method}">
 <input type="password" name="passphrase" autofocus autocomplete="current-password"
        placeholder="fraza zgody">
 <button type="submit">Zezwól</button>
 <div class="meta">przekierowanie: {redirect_uri}</div>
</form></body></html>
"""


def sse_frame(payload: str) -> bytes:
    return f"event: message\ndata: {payload}\n\n".encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "jarvis-mcp/1.0"

    # ---- plumbing -------------------------------------------------------
    def log_message(self, fmt, *args):
        log(f"{self.address_string()} {fmt % args}")

    def _send(self, status: int, body: bytes = b"", content_type: str = "application/json",
              headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # Cloudflare's edge pipelines onto a reused origin connection; a body it
        # re-delivers after a refusal then merges with the next request line.
        # One request per connection removes that whole class of smuggling.
        self.send_header("Connection", "close")
        self.close_connection = True
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status: int, payload, headers: dict | None = None) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                   "application/json", headers)

    def _read_body(self) -> bytes:
        """Read the request body exactly once and cache it.

        An early rejection (401/429) that skips the body leaves those bytes in
        the socket; on a keep-alive connection the next request line is then
        glued to them ("{...}GET /...") and the server answers 400/501. Every
        POST drains the body first, so rejection never corrupts the stream.
        """
        cached = getattr(self, "_body_cache", None)
        if cached is not None:
            return cached
        data = self._read_raw_body()
        self._body_cache = data
        return data

    def _read_raw_body(self) -> bytes:
        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            chunks = bytearray()
            while True:
                line = self.rfile.readline().strip()
                try:
                    size = int(line.split(b";")[0], 16)
                except ValueError:
                    break
                if size == 0:
                    self.rfile.readline()
                    break
                chunks += self.rfile.read(size)
                self.rfile.readline()
            return bytes(chunks)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(length) if 0 < length <= 8 * 1024 * 1024 else b""

    def _form(self) -> dict:
        raw = self._read_body().decode("utf-8", "replace")
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items() if values}

    # ---- GET ------------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if path == "/healthz":
            self._json(200, {"ok": True, "tools": len(core.visible_tools()),
                             "transport": "streamable-http", "read_only": READONLY})
            return
        if path == "/.well-known/oauth-authorization-server":
            self._json(200, metadata())
            return
        if path in ("/.well-known/oauth-protected-resource",
                    "/.well-known/oauth-protected-resource/mcp"):
            self._json(200, protected_resource())
            return
        if path == "/authorize":
            self._authorize_page(parsed)
            return
        if path == "/mcp":
            self._json(405, {"error": "no server-initiated stream"},
                       {"Allow": "POST, DELETE"})
            return
        self._json(404, {"error": "not found"})

    def _authorize_page(self, parsed) -> None:
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        state = load_state()
        client_id = (query.get("client_id") or [state["client_id"]])[0]
        redirect_uri = (query.get("redirect_uri")
                        or ["https://vertexaisearch.cloud.google.com/oauth-redirect"])[0]
        if client_id != state["client_id"]:
            self._json(400, {"error": "invalid_client"})
            return
        scope = " ".join(sorted(set((query.get("scope") or ["jarvis.read"])[0].split())
                                & set(SCOPES))) or "jarvis.read"
        page = CONSENT_PAGE.format(
            client_id=html.escape(client_id), scope=html.escape(scope),
            redirect_uri=html.escape(redirect_uri),
            state=html.escape((query.get("state") or [""])[0]),
            challenge=html.escape((query.get("code_challenge") or [""])[0]),
            method=html.escape((query.get("code_challenge_method") or ["plain"])[0]))
        self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")

    # ---- POST -----------------------------------------------------------
    def do_POST(self):
        self._read_body()  # always drain, even when the request is refused below
        path = urllib.parse.urlsplit(self.path).path
        if path == "/mcp":
            self._mcp()
            return
        if path == "/authorize":
            self._authorize_post()
            return
        if path == "/token":
            self._token()
            return
        self._json(404, {"error": "not found"})

    def do_DELETE(self):
        if urllib.parse.urlsplit(self.path).path != "/mcp":
            self._json(404, {"error": "not found"})
            return
        sid = self.headers.get("Mcp-Session-Id")
        if sid:
            with SESSION_LOCK:
                SESSIONS.pop(sid, None)
        self._send(204, b"")

    def _authorize_post(self) -> None:
        form = self._form()
        state = load_state()
        if form.get("client_id") != state["client_id"]:
            self._json(400, {"error": "invalid_client"})
            return
        if not passphrase_ok(state, form.get("passphrase", "")):
            log("consent refused: wrong passphrase")
            self._send(401, CONSENT_PAGE.format(
                client_id=html.escape(form.get("client_id", "")),
                scope=html.escape(form.get("scope", "jarvis.read")),
                redirect_uri=html.escape(form.get("redirect_uri", "")),
                state=html.escape(form.get("state", "")),
                challenge=html.escape(form.get("code_challenge", "")),
                method=html.escape(form.get("code_challenge_method", "plain")),
            ).encode("utf-8"), "text/html; charset=utf-8")
            return
        scope = " ".join(sorted(set((form.get("scope") or "jarvis.read").split())
                                & set(SCOPES))) or "jarvis.read"
        code = secrets.token_urlsafe(24)
        with SESSION_LOCK:
            CODES[code] = {"expires": time.time() + CODE_TTL, "scope": scope,
                           "redirect_uri": form.get("redirect_uri", ""),
                           "challenge": form.get("code_challenge", ""),
                           "method": form.get("code_challenge_method", "plain")}
        query = {"code": code}
        if form.get("state"):
            query["state"] = form["state"]
        location = form.get("redirect_uri", "") or public_url()
        joiner = "&" if urllib.parse.urlsplit(location).query else "?"
        log(f"consent granted, scope={scope}")
        self._send(302, b"", "text/plain", {"Location": location + joiner
                                            + urllib.parse.urlencode(query)})

    def _token(self) -> None:
        form = self._form()
        state = load_state()
        client_id = form.get("client_id", "")
        client_secret = form.get("client_secret", "")
        basic = self.headers.get("Authorization", "")
        if basic.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(basic.split(None, 1)[1]).decode()
                client_id, _, client_secret = decoded.partition(":")
            except (ValueError, IndexError):
                pass
        if client_id != state["client_id"] or not hmac.compare_digest(
                client_secret, state["client_secret"]):
            self._json(401, {"error": "invalid_client"})
            return
        grant = form.get("grant_type", "")
        if grant == "authorization_code":
            code = form.get("code", "")
            with SESSION_LOCK:
                row = CODES.pop(code, None)
            if not row or float(row["expires"]) < time.time():
                self._json(400, {"error": "invalid_grant"})
                return
            if row.get("redirect_uri") and form.get("redirect_uri") and \
                    form["redirect_uri"] != row["redirect_uri"]:
                self._json(400, {"error": "invalid_grant",
                                 "error_description": "redirect_uri mismatch"})
                return
            challenge = row.get("challenge") or ""
            if challenge:
                verifier = form.get("code_verifier", "")
                if not verifier:
                    self._json(400, {"error": "invalid_request",
                                     "error_description": "code_verifier required"})
                    return
                if row.get("method") == "S256":
                    digest = hashlib.sha256(verifier.encode()).digest()
                    expected = base64.urlsafe_b64encode(digest).decode().rstrip("=")
                else:
                    expected = verifier
                if not hmac.compare_digest(expected, challenge):
                    self._json(400, {"error": "invalid_grant",
                                     "error_description": "PKCE mismatch"})
                    return
            token, ttl = issue_access(row["scope"])
            self._json(200, {"access_token": token, "token_type": "Bearer",
                             "expires_in": ttl, "scope": row["scope"],
                             "refresh_token": issue_refresh(row["scope"], state)})
            return
        if grant == "refresh_token":
            token = form.get("refresh_token", "")
            with STATE_LOCK:
                row = (state.get("refresh") or {}).get(token)
                if row and float(row.get("expires") or 0) > time.time():
                    state["refresh"].pop(token, None)
                    save_state(state)
                else:
                    row = None
            if not row:
                self._json(400, {"error": "invalid_grant"})
                return
            access, ttl = issue_access(str(row.get("scope") or "jarvis.read"))
            self._json(200, {"access_token": access, "token_type": "Bearer",
                             "expires_in": ttl, "scope": row.get("scope"),
                             "refresh_token": issue_refresh(str(row.get("scope")), state)})
            return
        self._json(400, {"error": "unsupported_grant_type"})

    # ---- MCP ------------------------------------------------------------
    def _mcp(self) -> None:
        if not rate_ok(self.client_address[0]):
            self._json(429, {"error": "too many requests"})
            return
        scope = token_scope(self.headers.get("Authorization", ""))
        if not scope:
            self._json(401, {"error": "invalid_token"},
                       {"WWW-Authenticate":
                        f'Bearer realm="jarvis", resource_metadata="{public_url()}'
                        '/.well-known/oauth-protected-resource"'})
            return
        raw = self._read_body()
        try:
            message = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._json(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "Parse error"}})
            return
        is_notification_only = (
            isinstance(message, dict) and message.get("id") is None
            and isinstance(message.get("method"), str))
        denied = _scope_guard(message, set(scope.split()))
        if denied is not None:
            self._json(200, denied)
            return
        sid = self.headers.get("Mcp-Session-Id", "")
        headers = {}
        if isinstance(message, dict) and message.get("method") == "initialize":
            sid = secrets.token_urlsafe(18)
            now = time.time()
            with SESSION_LOCK:
                SESSIONS[sid] = now
                for key in [k for k, stamp in SESSIONS.items() if now - stamp > 3600]:
                    SESSIONS.pop(key, None)
                while len(SESSIONS) > MAX_SESSIONS:
                    SESSIONS.pop(next(iter(SESSIONS)))
            headers["Mcp-Session-Id"] = sid
        elif sid:
            with SESSION_LOCK:
                known = sid in SESSIONS
                if known:
                    SESSIONS[sid] = time.time()
            if not known:
                self._json(404, {"error": "unknown session"})
                return
        if is_notification_only:
            core.dispatch(message)
            self._send(202, b"", "application/json", headers)
            return
        reply = core.dispatch(message)
        if reply is None:
            self._send(202, b"", "application/json", headers)
            return
        payload = json.dumps(reply, ensure_ascii=False)
        accept = (self.headers.get("Accept") or "").lower()
        if "text/event-stream" in accept and "application/json" not in accept:
            self._send(200, sse_frame(payload), "text/event-stream", headers)
            return
        self._send(200, payload.encode("utf-8"), "application/json", headers)


def show_setup() -> int:
    state = load_state()
    base = public_url()
    print(f"public_url      : {base}")
    print(f"MCP server URL  : {base}/mcp")
    print(f"authorization   : {base}/authorize")
    print(f"token           : {base}/token")
    print(f"client_id       : {state['client_id']}")
    print(f"client_secret   : {state['client_secret']}")
    print(f"scopes          : {' '.join(SCOPES)}")
    print("redirect_uri    : https://vertexaisearch.cloud.google.com/oauth-redirect")
    print(f"state file      : {STATE_PATH}")
    return 0


def set_passphrase() -> int:
    if sys.stdin.isatty():
        import getpass
        phrase = getpass.getpass("Nowa fraza zgody Jarvis MCP: ")
    else:
        phrase = sys.stdin.readline().strip()
    if len(phrase) < 8:
        print("Fraza musi mieć co najmniej 8 znaków.", file=sys.stderr)
        return 1
    state = load_state()
    state["passphrase_hash"] = _hash(phrase, state["salt"])
    state.pop("passphrase_generated", None)
    save_state(state)
    print("Fraza zgody zaktualizowana.")
    return 0


def serve() -> int:
    state = load_state()
    core.READONLY = READONLY
    tools = core.visible_tools()
    log(f"jarvis-mcp http on {HOST}:{PORT} public={public_url()} "
        f"tools={len(tools)} read_only={READONLY} anon={ANON}")
    log(f"client_id={state['client_id']} state={STATE_PATH}")
    if ANON:
        log("WARNING: JARVIS_MCP_HTTP_ANON=1 — /mcp accepts unauthenticated calls")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("stopping")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--show-setup" in args:
        sys.exit(show_setup())
    if "--set-passphrase" in args:
        sys.exit(set_passphrase())
    sys.exit(serve())
