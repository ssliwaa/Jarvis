"""MCP client for local stdio and remote HTTP servers.

Servers are declared in ``~/.jarvis-tools/mcp.json``. Three transports are
supported:

* ``stdio`` — a local child process speaking newline-delimited JSON-RPC (with a
  ``Content-Length`` fallback). This is the original Jarvis transport.
* ``http`` — the MCP Streamable HTTP transport (protocol 2025-03-26): JSON-RPC
  over POST, with a JSON or ``text/event-stream`` response and an
  ``Mcp-Session-Id`` header for the session.
* ``sse`` — the legacy HTTP+SSE transport (protocol 2024-11-05): a long-lived
  GET stream announces a POST endpoint, responses arrive on that stream.

Remote servers can authenticate with a static bearer token from an environment
variable or with OAuth 2.1 (discovery, dynamic client registration, PKCE,
refresh tokens). Tokens are stored in ``mcp-oauth.json`` beside the config, mode
0600, and are never returned by ``config()`` or ``status()``.

Security model: every remote URL is validated before use. Public endpoints must
be HTTPS and resolve only to public addresses; the connection is pinned to the
validated IP so a second DNS answer cannot move it. HTTP redirects are refused,
so an Authorization header is never replayed to another origin. Private/LAN
endpoints require an explicit ``"allow_private": true`` in the user-owned
config. Every tool call remains an external side effect and is gated by the
Operator's approval layer.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import http.server
import json
import os
import re
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections import deque
from pathlib import Path

import net_guard

CONFIG_PATH = Path(os.environ.get("JARVIS_MCP_CONFIG")
                   or (Path.home() / ".jarvis-tools" / "mcp.json"))
TOKEN_FILE_NAME = "mcp-oauth.json"
PROTOCOL_VERSION = "2025-03-26"
LEGACY_PROTOCOL_VERSION = "2024-11-05"
MAX_REQUEST_BYTES = 8_000_000
MAX_RESPONSE_BYTES = 8_000_000
MAX_SSE_BYTES = 8_000_000
MAX_TOOL_ARGUMENTS = 1_024_000
MAX_TOOLS = 2000
MAX_TOOL_PAGES = 20
DEFAULT_TIMEOUT = 20.0
DEFAULT_SCHEMA_TTL = 300.0
DEFAULT_COOLDOWN = 10.0
DEFAULT_RETRIES = 2
USER_AGENT = "jarvis-mcp/1.0"
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,80}$")
_FORBIDDEN_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "mcp-session-id", "mcp-protocol-version",
}

EOF_MARKER = object()


class MCPError(Exception):
    pass


class MCPAuthRequired(MCPError):
    """The remote server needs an OAuth authorization or a refreshed token."""

    def __init__(self, server: str, message: str = ""):
        self.server = server
        super().__init__(message or (
            f"MCP server {server} requires OAuth. Run: "
            f"python3 mcp_client.py auth {server}"))


class MCPNetworkError(MCPError):
    pass


class _HTTPStatusError(MCPError):
    def __init__(self, status: int, headers, body: str):
        self.status = int(status)
        self.headers = headers
        self.body = str(body or "")[:4000]
        super().__init__(f"MCP server returned HTTP {self.status}.")


def _env_float(name: str, default: float) -> float:
    try:
        return max(0.0, float(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return float(default)


def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return int(default)


def _freeze(value):
    """A hashable, comparable form for reload() spec checks."""
    if isinstance(value, dict):
        return tuple(sorted((str(key), _freeze(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _clean_headers(value) -> dict:
    if not isinstance(value, dict):
        return {}
    output = {}
    for key, item in list(value.items())[:40]:
        name = str(key)
        if not _HEADER_NAME.match(name) or name.lower() in _FORBIDDEN_HEADERS:
            continue
        output[name] = str(item)[:4000]
    return output


def _redact(text, secrets_list) -> str:
    output = str(text or "")
    for secret in secrets_list:
        secret = str(secret or "")
        if len(secret) >= 6:
            output = output.replace(secret, "[REDACTED]")
    return output


def _sensitive_header_values(headers) -> list:
    output = []
    for name, value in (headers or {}).items():
        lowered = str(name).casefold()
        if any(word in lowered for word in (
                "authorization", "cookie", "token", "secret", "key", "password")):
            output.append(value)
    return output


def _safe_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
        port = f":{parsed.port}" if parsed.port else ""
        host = parsed.hostname
    except ValueError:
        return "[invalid URL]"
    if not parsed.scheme or not host:
        return "[invalid URL]"
    path = parsed.path or "/"
    return f"{parsed.scheme}://{host}{port}{path}"


def _same_resource(left, right) -> bool:
    def normalized(value):
        try:
            parsed = urllib.parse.urlsplit(str(value or ""))
        except ValueError:
            return None
        if not parsed.scheme or not parsed.hostname:
            return None
        return (parsed.scheme.casefold(), parsed.netloc.casefold(),
                (parsed.path or "/").rstrip("/") or "/", parsed.query)

    if not left or not right:
        return False
    return normalized(left) == normalized(right)


def _same_origin(left, right) -> bool:
    try:
        a, b = urllib.parse.urlsplit(left), urllib.parse.urlsplit(right)
    except ValueError:
        return False
    return (a.scheme.casefold() == b.scheme.casefold()
            and (a.hostname or "").casefold() == (b.hostname or "").casefold()
            and (a.port or (443 if a.scheme.casefold() == "https" else 80))
            == (b.port or (443 if b.scheme.casefold() == "https" else 80)))


def _validate_url(url: str, allow_private: bool = False, what: str = "MCP endpoint") -> None:
    """Reject non-HTTP(S), credentialed and non-public remote targets."""
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
        parsed.port  # a malformed or out-of-range port is invalid, not a hostname
    except ValueError:
        raise MCPError(f"The {what} URL is invalid.") from None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise MCPError(f"The {what} must be an http(s) URL.")
    if parsed.username is not None or parsed.password is not None:
        raise MCPError(f"The {what} URL must not embed credentials.")
    if allow_private:
        return
    if parsed.scheme != "https":
        raise MCPError(f"The {what} must use HTTPS unless allow_private is true.")
    if not net_guard.is_public_host(parsed.hostname):
        raise MCPError(f"The {what} host is not publicly routable.")


# ---------------------------------------------------------------------------
# Pinned HTTP opener
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """MCP endpoints do not need redirects; refusing them protects the token."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            newurl, 403, "MCP endpoints must not redirect", headers, fp)


_PinnedHTTPConnection = net_guard.PinnedHTTPConnection
_PinnedHTTPSConnection = net_guard.PinnedHTTPSConnection
_PinnedHTTPHandler = net_guard.PinnedHTTPHandler
_PinnedHTTPSHandler = net_guard.PinnedHTTPSHandler


def _opener(allow_private: bool):
    return urllib.request.build_opener(
        _PinnedHTTPHandler(allow_private), _PinnedHTTPSHandler(allow_private),
        _NoRedirect(), urllib.request.ProxyHandler({}))


def _open_http(url: str, method: str = "GET", headers=None, body=None,
               timeout: float = DEFAULT_TIMEOUT, allow_private: bool = False):
    _validate_url(url, allow_private)
    request = urllib.request.Request(
        url, data=body, headers=dict(headers or {}), method=method)
    try:
        return _opener(allow_private).open(
            request, timeout=max(1.0, min(float(timeout), 300.0)))
    except urllib.error.HTTPError as error:
        try:
            detail = error.read(4096)
        except Exception:
            detail = b""
        finally:
            try:
                error.close()
            except Exception:
                pass
        raise _HTTPStatusError(
            error.code, error.headers, detail.decode("utf-8", errors="replace")) from None
    except urllib.error.URLError as error:
        raise MCPNetworkError(
            f"MCP network error: {type(error.reason).__name__}") from None
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise MCPNetworkError(f"MCP network error: {type(error).__name__}") from None


def _close_now(response) -> None:
    """Close a streaming response and unblock a reader parked in readline()."""
    if response is None:
        return
    try:
        response.fp.raw._sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        response.close()
    except Exception:
        pass


def _read_limited(response, limit: int, label: str = "MCP response") -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = response.read(min(65536, limit - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise MCPError(f"The {label} exceeded the {limit} byte limit.")
        chunks.append(chunk)
    return b"".join(chunks)


def _iter_sse(response, deadline: float | None = None, max_events: int = 10000):
    """Yield ``(event, data, id)`` tuples from a text/event-stream response."""
    event, data, event_id = "message", [], None
    total = 0
    seen = 0
    while True:
        if deadline is not None and time.time() > deadline:
            raise MCPError("The MCP stream timed out.")
        raw = response.readline(65537)
        if not raw:
            break
        if len(raw) > 65536:
            raise MCPError("The MCP server sent an oversized SSE line.")
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if not line:
            if data:
                payload = "\n".join(data)
                total += len(payload)
                seen += 1
                if total > MAX_SSE_BYTES:
                    raise MCPError("The MCP stream exceeded its size limit.")
                if seen > max_events:
                    raise MCPError("The MCP stream sent too many events.")
                yield event, payload, event_id
            event, data, event_id = "message", [], None
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "event":
            event = value or "message"
        elif field == "data":
            data.append(value)
        elif field == "id":
            event_id = value
    if data:
        payload = "\n".join(data)
        if len(payload) > MAX_SSE_BYTES:
            raise MCPError("The MCP stream exceeded its size limit.")
        yield event, payload, event_id


def _messages_from_value(value) -> list[dict]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _messages_from_text(text: str) -> list[dict]:
    try:
        return _messages_from_value(json.loads(text))
    except (ValueError, UnicodeError) as error:
        raise MCPError(f"MCP response is not valid JSON: {error}") from None


def _response_message(messages, request_id):
    for message in messages:
        if isinstance(message, dict) and message.get("id") == request_id:
            return message
    return None


def _raise_rpc_error(message):
    error = message.get("error")
    text = error.get("message") if isinstance(error, dict) else str(error)
    raise MCPError(str(text or error))


def _list_all_tools(rpc) -> list[dict]:
    tools, cursor = [], None
    for _ in range(MAX_TOOL_PAGES):
        result = rpc("tools/list", {"cursor": cursor} if cursor else {})
        if not isinstance(result, dict):
            break
        listing = result.get("tools")
        if isinstance(listing, list):
            tools.extend(item for item in listing if isinstance(item, dict))
        cursor = result.get("nextCursor")
        if not isinstance(cursor, str) or not cursor or len(tools) >= MAX_TOOLS:
            break
    return tools[:MAX_TOOLS]


def _call_tool(rpc, name: str, arguments=None):
    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise MCPError("MCP tool arguments must be an object.")
    if len(json.dumps(arguments, ensure_ascii=False).encode("utf-8")) > MAX_TOOL_ARGUMENTS:
        raise MCPError("MCP tool arguments are larger than the 512 KB limit.")
    return rpc("tools/call", {"name": name, "arguments": arguments})


# ---------------------------------------------------------------------------
# stdio transport
# ---------------------------------------------------------------------------

class MCPProcess:
    MAX_BUFFER = 8 * 1024 * 1024

    def __init__(self, name: str, command: str, args: list | None = None,
                 env: dict | None = None, cwd: str | None = None):
        self.name = name
        self.command = command
        self.args = list(args or [])
        # Do not hand the provider key, SSH agent or other host secrets to a
        # third-party MCP server. Only the session basics needed to run it.
        base_env = {key: os.environ[key] for key in (
            "PATH", "HOME", "LANG", "LC_ALL", "TERM", "XDG_RUNTIME_DIR",
            "DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS",
        ) if key in os.environ}
        self.env = {**base_env, **(env or {})}
        self.cwd = cwd
        # Raw spec, used by reload() to notice a changed command/args/env/cwd.
        self.spec = (str(command), tuple(self.args), dict(env or {}), cwd)
        self.process = None
        self.lock = threading.RLock()
        self._next_id = 0
        self._initialized = False
        self.server_info = {}
        self._recv = b""
        self._stderr = deque(maxlen=120)

    @property
    def running(self) -> bool:
        return bool(self._initialized and self.process and self.process.poll() is None)

    def start(self):
        with self.lock:
            if self.process and self.process.poll() is None and self._initialized:
                return self.server_info
            if self.process and self.process.poll() is None:
                # A previous initialize timed out. Reusing that child left the
                # server permanently unusable until Jarvis restarted.
                self.close()
            self._recv = b""
            self._initialized = False
            self.process = subprocess.Popen(
                [self.command, *self.args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=False, env=self.env, cwd=self.cwd,
                start_new_session=True)
            threading.Thread(target=self._drain_stderr, name=f"mcp-{self.name}-stderr",
                             daemon=True).start()
            try:
                response = self._request("initialize", {
                    "protocolVersion": LEGACY_PROTOCOL_VERSION, "capabilities": {},
                    "clientInfo": {"name": "jarvis", "version": "1.0"}}, timeout=15)
                self.server_info = response.get("serverInfo", {}) if isinstance(response, dict) else {}
                self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
                self._initialized = True
            except Exception:
                self.close()
                raise
            return self.server_info

    def _drain_stderr(self):
        """Keep the stderr pipe empty so a chatty server can never deadlock."""
        try:
            for raw in iter(self.process.stderr.readline, b""):
                line = raw.decode("utf-8", errors="replace").strip()
                if line:
                    self._stderr.append(line[-200:])
        except (OSError, ValueError):
            pass

    def _send(self, payload):
        if not self.process or self.process.poll() is not None:
            raise MCPError(f"MCP server {self.name} is not running.")
        data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        if len(data) > MAX_REQUEST_BYTES:
            raise MCPError("The MCP request is larger than the 1 MB limit.")
        try:
            descriptor = self.process.stdin.fileno()
        except (AttributeError, OSError, ValueError):
            raise MCPError("The MCP input pipe is unavailable.") from None
        deadline = time.time() + 10.0
        try:
            os.set_blocking(descriptor, False)
            while data:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise MCPError("Timed out writing the request to the MCP server.")
                _, writable, _ = select.select([], [descriptor], [], remaining)
                if not writable:
                    raise MCPError("Timed out writing the request to the MCP server.")
                try:
                    written = os.write(descriptor, data)
                except BlockingIOError:
                    continue
                data = data[written:]
        except (OSError, ValueError) as error:
            raise MCPError(f"MCP write failed: {error}") from None
        finally:
            try:
                os.set_blocking(descriptor, True)
            except (OSError, ValueError):
                pass

    def _fill(self, deadline):
        """Read more transport bytes into the buffer, respecting the deadline."""
        if len(self._recv) > self.MAX_BUFFER:
            raise MCPError("The MCP server sent an oversized response.")
        remaining = deadline - time.time()
        if remaining <= 0:
            return False
        ready, _, _ = select.select([self.process.stdout], [], [], min(remaining, 0.5))
        if not ready:
            return True  # keep waiting
        os.set_blocking(self.process.stdout.fileno(), False)
        try:
            chunk = self.process.stdout.read1(65536)
        finally:
            os.set_blocking(self.process.stdout.fileno(), True)
        if not chunk:
            raise MCPError(f"MCP server {self.name} closed its output.")
        self._recv += chunk
        return True

    def _read_message(self, deadline):
        """Parse one message: newline-delimited JSON, or Content-Length framing."""
        while True:
            text = None
            if self._recv.startswith(b"{"):
                head, newline, tail = self._recv.partition(b"\n")
                if newline:
                    text = head
                    self._recv = tail
            elif self._recv and not self._recv.lower().startswith(b"content-length:"):
                # Noise on our main stream: skip to the next newline.
                _, newline, tail = self._recv.partition(b"\n")
                self._recv = tail if newline else b"="
            if text is not None:
                try:
                    return json.loads(text.decode("utf-8"))
                except (ValueError, UnicodeError) as error:
                    raise MCPError(f"MCP response is not valid JSON: {error}") from None
            # Content-Length framing (fall back) or header noise.
            if b"\r\n\r\n" in self._recv:
                head, _, tail = self._recv.partition(b"\r\n\r\n")
                if head and not self._recv.startswith(b"{"):
                    length = None
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            try:
                                length = int(line.split(b":", 1)[1].strip())
                            except ValueError:
                                raise MCPError("Bad MCP Content-Length header.") from None
                    if length is None:
                        raise MCPError("MCP response has no JSON body.")
                    if len(tail) < length:
                        if not self._fill(deadline):
                            raise MCPError("MCP request timed out waiting for the body.")
                        continue
                    payload, self._recv = tail[:length], tail[length:]
                    try:
                        return json.loads(payload.decode("utf-8"))
                    except (ValueError, UnicodeError) as error:
                        raise MCPError(f"MCP response is not valid JSON: {error}") from None
            if not self._fill(deadline):
                raise MCPError("MCP request timed out: no response arrived.")

    def _request(self, method, params=None, timeout=20):
        with self.lock:
            self._next_id += 1
            request_id = self._next_id
            self._send({"jsonrpc": "2.0", "id": request_id, "method": method,
                        "params": params or {}})
            deadline = time.time() + max(1.0, float(timeout))
            while True:
                message = self._read_message(deadline)
                if not isinstance(message, dict):
                    continue  # guard against a server emitting scalars/lists
                if message.get("id") != request_id:
                    continue
                if "error" in message:
                    _raise_rpc_error(message)
                return message.get("result", {})

    def list_tools(self):
        return _list_all_tools(self._request)

    def call_tool(self, name, arguments=None):
        return _call_tool(self._request, name, arguments)

    def ping(self):
        return self._request("ping", {})

    def close(self):
        # Serialize with an in-flight _request on the same lock; setting
        # process=None underneath a read produced AttributeError/fd errors.
        with self.lock:
            process, self.process = self.process, None
            self._initialized = False
            if not process:
                return
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                try:
                    process.terminate()
                except OSError:
                    pass
            try:
                process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    try:
                        process.kill()
                    except OSError:
                        pass
                try:
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            for stream in (process.stdin, process.stdout, process.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# OAuth 2.1 for remote MCP servers
# ---------------------------------------------------------------------------

class _TokenStore:
    """Atomic, 0600 token storage beside the MCP config."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock = threading.RLock()

    def _read(self) -> dict:
        try:
            if stat.S_IMODE(self.path.stat().st_mode) & 0o077:
                os.chmod(self.path, 0o600)
        except OSError:
            pass
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        servers = payload.get("servers")
        return servers if isinstance(servers, dict) else {}

    def get(self, name: str) -> dict | None:
        with self.lock:
            record = self._read().get(str(name))
            return dict(record) if isinstance(record, dict) else None

    def set(self, name: str, record: dict) -> None:
        with self.lock:
            servers = self._read()
            servers[str(name)] = dict(record)
            self._write({"version": 1, "servers": servers})

    def delete(self, name: str) -> None:
        with self.lock:
            servers = self._read()
            if servers.pop(str(name), None) is not None:
                self._write({"version": 1, "servers": servers})

    def _write(self, payload: dict) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise MCPError(f"The MCP token directory is unavailable: {error}") from None
        temporary = self.path.with_name(
            f"{self.path.name}.tmp-{secrets.token_hex(6)}")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except OSError as error:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise MCPError(f"Could not write the MCP token store: {error}") from None


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != getattr(self.server, "callback_path", "/callback"):
            self.send_error(404)
            return
        try:
            host = urllib.parse.urlsplit(
                "//" + str(self.headers.get("Host") or "")).hostname or ""
        except ValueError:
            host = ""
        if host.casefold() not in ("127.0.0.1", "localhost", "::1"):
            self.send_error(400)
            return
        query = urllib.parse.parse_qs(parsed.query)
        for key in ("code", "state", "error", "error_description"):
            self.server.oauth_result[key] = query.get(key, [""])[0]
        body = b"Jarvis MCP authorization received. You can close this tab."
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        self.server.oauth_event.set()

    def log_message(self, *args):
        pass


class _CallbackServer:
    """Loopback redirect listener for the authorization-code flow."""

    def __init__(self, redirect_uri: str | None = None):
        host, port, callback_path = "127.0.0.1", 0, "/callback"
        if redirect_uri:
            parsed = urllib.parse.urlsplit(str(redirect_uri))
            if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
                raise MCPError("oauth.redirect_uri must be a loopback http URL.")
            if parsed.query or parsed.fragment:
                raise MCPError("oauth.redirect_uri must not have a query or fragment.")
            host = "::1" if parsed.hostname == "::1" else "127.0.0.1"
            port = parsed.port
            if not port:
                raise MCPError("oauth.redirect_uri must name an explicit port.")
            callback_path = parsed.path or "/callback"
        self.event = threading.Event()
        self.result = {}

        class _CallbackHTTPServer(http.server.HTTPServer):
            address_family = socket.AF_INET6 if host == "::1" else socket.AF_INET

        try:
            self.httpd = _CallbackHTTPServer((host, port), _CallbackHandler)
        except OSError as error:
            raise MCPError(
                f"Could not open the OAuth callback listener: {error}") from None
        self.httpd.callback_path = callback_path
        self.httpd.oauth_event = self.event
        self.httpd.oauth_result = self.result
        if redirect_uri:
            self.redirect_uri = str(redirect_uri)
        else:
            self.redirect_uri = f"http://127.0.0.1:{self.httpd.server_port}{callback_path}"
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.1},
            name="jarvis-mcp-oauth", daemon=True)
        self.thread.start()

    def wait(self, timeout: float = 300.0) -> dict:
        self.event.wait(max(1.0, float(timeout)))
        return dict(self.result)

    def close(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass
        try:
            self.httpd.server_close()
        except Exception:
            pass
        self.thread.join(timeout=2)


def _pkce_pair():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _add_query(url: str, params: dict) -> str:
    parsed = urllib.parse.urlsplit(str(url))
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.extend((key, value) for key, value in params.items() if value is not None)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path,
         urllib.parse.urlencode(query), parsed.fragment))


def _scope_string(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " ".join(str(item).strip() for item in value if str(item).strip())
    return str(value).strip()


def _resource_metadata_candidates(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = (parsed.path or "").rstrip("/")
    output = []
    if path and path != "/":
        output.append(f"{origin}/.well-known/oauth-protected-resource{path}")
    output.append(f"{origin}/.well-known/oauth-protected-resource")
    return output


def _auth_server_candidates(issuer: str) -> list[str]:
    parsed = urllib.parse.urlsplit(issuer)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = (parsed.path or "").rstrip("/")
    output = []
    if path and path != "/":
        output.append(f"{origin}/.well-known/oauth-authorization-server{path}")
    output.append(f"{origin}/.well-known/oauth-authorization-server")
    if path and path != "/":
        output.append(f"{origin}{path}/.well-known/openid-configuration")
    output.append(f"{origin}/.well-known/openid-configuration")
    return list(dict.fromkeys(output))


class _OAuthClient:
    def __init__(self, server: str, url: str, settings, allow_private: bool,
                 store: _TokenStore):
        self.server = server
        self.url = str(url)
        self.settings = dict(settings) if isinstance(settings, dict) else {}
        self.allow_private = bool(allow_private)
        self.store = store
        self.lock = threading.RLock()

    def _required(self) -> MCPAuthRequired:
        return MCPAuthRequired(
            self.server,
            f"MCP server {self.server} requires OAuth. Run: "
            f"python3 mcp_client.py auth {self.server}")

    def _record(self) -> dict | None:
        record = self.store.get(self.server)
        if not isinstance(record, dict):
            return None
        if not _same_resource(record.get("resource"), self.url):
            return None
        return record

    def _known_secrets(self) -> list:
        record = self._record() or {}
        return [record.get("access_token"), record.get("refresh_token"),
                record.get("client_secret")]

    def auth_state(self) -> str:
        record = self._record()
        if not record:
            return "required"
        try:
            expires = float(record.get("expires_at") or 0)
        except (TypeError, ValueError):
            expires = 0.0
        if record.get("access_token") and (not expires or expires > time.time() + 30):
            return "authorized"
        if record.get("refresh_token") and record.get("token_endpoint"):
            return "refreshable"
        return "expired"

    def access_token(self) -> str:
        with self.lock:
            record = self._record()
            if not record:
                raise self._required()
            token = str(record.get("access_token") or "")
            try:
                expires = float(record.get("expires_at") or 0)
            except (TypeError, ValueError):
                expires = 0.0
            if token and (not expires or expires > time.time() + 30):
                return token
            if record.get("refresh_token") and record.get("token_endpoint"):
                return self._refresh(record)
            raise self._required()

    def refresh(self) -> str:
        with self.lock:
            record = self._record()
            if not record or not record.get("refresh_token") or not record.get("token_endpoint"):
                raise self._required()
            return self._refresh(record)

    def _refresh(self, record: dict) -> str:
        data = {
            "grant_type": "refresh_token",
            "refresh_token": str(record.get("refresh_token") or ""),
        }
        if record.get("scope"):
            data["scope"] = str(record["scope"])
        if record.get("resource"):
            data["resource"] = str(record["resource"])
        payload = self._token_call(record, data)
        return self._store_tokens(record, payload)

    def _token_call(self, record: dict, data: dict) -> dict:
        endpoint = str(record.get("token_endpoint")
                       or self.settings.get("token_endpoint") or "")
        if not endpoint:
            metadata = self.discover()
            endpoint = str(metadata.get("token_endpoint") or "")
        if not endpoint:
            raise MCPError(
                f"No OAuth token endpoint is configured for MCP server {self.server}.")
        _validate_url(endpoint, self.allow_private, "OAuth token endpoint")
        client_id = str(record.get("client_id")
                        or self.settings.get("client_id") or "")
        client_secret = str(record.get("client_secret")
                            or self.settings.get("client_secret") or "")
        method = str(record.get("token_endpoint_auth_method")
                     or self.settings.get("token_endpoint_auth_method")
                     or ("client_secret_basic" if client_secret else "none"))
        if not client_id:
            raise MCPError(
                f"No OAuth client id is stored for MCP server {self.server}; "
                "run the auth command first.")
        form = dict(data)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        if client_secret and method == "client_secret_basic":
            raw = f"{client_id}:{client_secret}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        else:
            form["client_id"] = client_id
            if client_secret and method != "none":
                form["client_secret"] = client_secret
        body = urllib.parse.urlencode(form).encode("utf-8")
        try:
            response = _open_http(endpoint, "POST", headers, body,
                                  timeout=20, allow_private=self.allow_private)
            try:
                raw = _read_limited(response, MAX_RESPONSE_BYTES,
                                    "OAuth token response")
            finally:
                response.close()
        except _HTTPStatusError as error:
            detail = _redact(error.body, self._known_secrets())
            raise MCPAuthRequired(
                self.server,
                f"OAuth token request for {self.server} failed: HTTP {error.status} "
                f"{detail[:300]}") from None
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise MCPError(
                f"The OAuth token endpoint for {self.server} returned invalid JSON.") from None
        if not isinstance(payload, dict):
            raise MCPError(
                f"The OAuth token endpoint for {self.server} returned no token object.")
        if payload.get("error"):
            description = _redact(payload.get("error_description") or "",
                                  self._known_secrets())
            raise MCPAuthRequired(
                self.server,
                f"OAuth authorization for {self.server} failed: "
                f"{payload.get('error')} {description[:300]}".strip())
        return payload

    def _store_tokens(self, record: dict, payload: dict) -> str:
        token = str(payload.get("access_token") or "")
        if not token:
            raise MCPError(
                f"The OAuth token endpoint for {self.server} returned no access token.")
        token_type = str(payload.get("token_type") or "bearer").casefold()
        if token_type != "bearer":
            raise MCPError(
                f"The OAuth endpoint for {self.server} returned a non-bearer token.")
        expires_at = 0.0
        if payload.get("expires_in") is not None:
            try:
                expires_at = time.time() + max(0.0, float(payload["expires_in"]) - 30.0)
            except (TypeError, ValueError):
                expires_at = 0.0
        updated = dict(record)
        updated.update({
            "access_token": token,
            "expires_at": expires_at,
            "resource": self.url,
            "updated_at": time.time(),
        })
        if payload.get("refresh_token"):
            updated["refresh_token"] = str(payload["refresh_token"])
        if payload.get("scope"):
            updated["scope"] = str(payload["scope"])
        self.store.set(self.server, updated)
        return token

    def _get_json(self, url: str, what: str) -> dict:
        try:
            response = _open_http(
                url, "GET", {"Accept": "application/json"}, None,
                timeout=15, allow_private=self.allow_private)
            try:
                body = _read_limited(response, MAX_RESPONSE_BYTES, what)
            finally:
                response.close()
        except (MCPError, _HTTPStatusError):
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def discover(self) -> dict:
        """Resolve protected-resource and authorization-server metadata."""
        authorization = str(self.settings.get("authorization_endpoint") or "")
        token = str(self.settings.get("token_endpoint") or "")
        if authorization and token:
            parsed = urllib.parse.urlsplit(self.url)
            return {
                "authorization_endpoint": authorization,
                "token_endpoint": token,
                "registration_endpoint": self.settings.get("registration_endpoint"),
                "issuer": (self.settings.get("issuer")
                           or f"{parsed.scheme}://{parsed.netloc}"),
                "scopes_supported": self.settings.get("scopes_supported"),
            }

        resource_metadata = {}
        hint = self.settings.get("resource_metadata")
        candidates = [str(hint)] if hint else _resource_metadata_candidates(self.url)
        for candidate in candidates:
            value = self._get_json(candidate, "OAuth resource metadata")
            if value.get("authorization_servers") or value.get("scopes_supported"):
                resource_metadata = value
                break

        issuer = str(self.settings.get("issuer") or "")
        servers = resource_metadata.get("authorization_servers")
        if not issuer and isinstance(servers, list) and servers:
            issuer = str(servers[0] or "")
        if not issuer:
            parsed = urllib.parse.urlsplit(self.url)
            issuer = f"{parsed.scheme}://{parsed.netloc}"

        metadata = {}
        for candidate in _auth_server_candidates(issuer):
            value = self._get_json(candidate, "OAuth server metadata")
            if value.get("authorization_endpoint") and value.get("token_endpoint"):
                metadata = value
                break
        if not metadata:
            raise MCPError(
                f"Could not discover OAuth endpoints for MCP server {self.server}. "
                "Set oauth.authorization_endpoint and oauth.token_endpoint in mcp.json.")
        metadata = dict(metadata)
        metadata.setdefault("issuer", issuer)
        if resource_metadata.get("scopes_supported"):
            metadata.setdefault("scopes_supported", resource_metadata["scopes_supported"])
        return metadata

    def _register(self, endpoint: str, redirect_uri: str) -> dict:
        _validate_url(endpoint, self.allow_private, "OAuth registration endpoint")
        body = json.dumps({
            "client_name": "Jarvis",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }, ensure_ascii=False).encode("utf-8")
        try:
            response = _open_http(
                endpoint, "POST",
                {"Content-Type": "application/json", "Accept": "application/json"},
                body, timeout=20, allow_private=self.allow_private)
            try:
                raw = _read_limited(response, MAX_RESPONSE_BYTES,
                                    "OAuth registration response")
            finally:
                response.close()
        except _HTTPStatusError as error:
            raise MCPError(
                f"OAuth client registration for {self.server} failed: "
                f"HTTP {error.status}.") from None
        try:
            value = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise MCPError(
                f"OAuth client registration for {self.server} returned invalid JSON.") from None
        if not isinstance(value, dict) or not value.get("client_id"):
            raise MCPError(
                f"OAuth client registration for {self.server} returned no client_id.")
        return value

    def authorize(self, open_browser: bool = True, notify=None) -> dict:
        """Run the authorization-code + PKCE flow on a loopback redirect."""
        with self.lock:
            callback = _CallbackServer(self.settings.get("redirect_uri"))
            try:
                metadata = self.discover()
                authorization = str(metadata.get("authorization_endpoint") or "")
                token = str(metadata.get("token_endpoint") or "")
                if not authorization or not token:
                    raise MCPError(
                        f"OAuth metadata for {self.server} is incomplete.")
                _validate_url(authorization, self.allow_private,
                              "OAuth authorization endpoint")
                _validate_url(token, self.allow_private, "OAuth token endpoint")

                record = self._record() or {}
                client_id = str(record.get("client_id")
                                or self.settings.get("client_id") or "")
                client_secret = str(record.get("client_secret")
                                    or self.settings.get("client_secret") or "")
                method = str(metadata.get("token_endpoint_auth_method")
                             or self.settings.get("token_endpoint_auth_method")
                             or ("client_secret_basic" if client_secret else "none"))
                if not client_id:
                    registration = str(metadata.get("registration_endpoint")
                                       or self.settings.get("registration_endpoint") or "")
                    if not registration:
                        raise MCPError(
                            f"MCP server {self.server} does not advertise dynamic "
                            "client registration; set oauth.client_id in mcp.json.")
                    client = self._register(registration, callback.redirect_uri)
                    client_id = str(client.get("client_id"))
                    client_secret = str(client.get("client_secret") or "")
                    method = str(client.get("token_endpoint_auth_method") or method)

                verifier, challenge = _pkce_pair()
                state = secrets.token_urlsafe(32)
                scope = _scope_string(self.settings.get("scopes")
                                      or self.settings.get("scope"))
                params = {
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": callback.redirect_uri,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": state,
                    "resource": self.url,
                }
                if scope:
                    params["scope"] = scope
                url = _add_query(authorization, params)
                if notify:
                    notify(url)
                if open_browser:
                    try:
                        webbrowser.open(url, new=2)
                    except Exception:
                        pass
                result = callback.wait(300)
                if not result:
                    raise MCPAuthRequired(
                        self.server,
                        f"OAuth authorization for {self.server} timed out.")
                if result.get("error"):
                    description = _redact(result.get("error_description") or "",
                                          self._known_secrets())
                    raise MCPAuthRequired(
                        self.server,
                        f"OAuth authorization for {self.server} failed: "
                        f"{result.get('error')} {description[:300]}".strip())
                if not hmac.compare_digest(str(result.get("state") or ""), state):
                    raise MCPAuthRequired(
                        self.server,
                        f"OAuth state mismatch for {self.server}; nothing was stored.")
                code = str(result.get("code") or "")
                if not code:
                    raise MCPAuthRequired(
                        self.server,
                        f"OAuth authorization for {self.server} returned no code.")
                record = {
                    "resource": self.url,
                    "issuer": metadata.get("issuer"),
                    "token_endpoint": token,
                    "authorization_endpoint": authorization,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "token_endpoint_auth_method": method,
                    "scope": scope,
                }
                payload = self._token_call(record, {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": callback.redirect_uri,
                    "code_verifier": verifier,
                    "resource": self.url,
                })
                self._store_tokens(record, payload)
                return {
                    "server": self.server,
                    "authorized": True,
                    "scope": payload.get("scope") or scope,
                }
            finally:
                callback.close()


# ---------------------------------------------------------------------------
# Remote transports
# ---------------------------------------------------------------------------

class _RemoteMCP:
    kind = "http"

    def __init__(self, name: str, url: str, headers=None, token_env: str = "",
                 oauth=None, allow_private: bool = False,
                 store: _TokenStore | None = None, timeout: float | None = None):
        _validate_url(url, allow_private)
        self.name = name
        self.url = str(url)
        self.allow_private = bool(allow_private)
        self.headers = _clean_headers(headers)
        self.token_env = str(token_env or "")
        self.oauth = (_OAuthClient(name, url, oauth, allow_private, store)
                      if oauth is not None and store is not None else None)
        self.timeout = float(timeout or _env_float("JARVIS_MCP_TIMEOUT", DEFAULT_TIMEOUT))
        self.spec = ("remote", self.kind, self.url, _freeze(self.headers),
                     oauth is not None,
                     _freeze(oauth if isinstance(oauth, dict) else {}),
                     self.allow_private, self.token_env)
        self.server_info = {}
        self._initialized = False
        self._next_id = 0
        self.lock = threading.RLock()

    @property
    def running(self) -> bool:
        return bool(self._initialized)

    def _auth_headers(self) -> dict:
        if self.headers.get("Authorization"):
            return {}
        if self.token_env:
            token = os.environ.get(self.token_env, "").strip()
            if not token:
                raise MCPError(
                    f"The environment variable {self.token_env} for MCP server "
                    f"{self.name} is not set.")
            return {"Authorization": f"Bearer {token}"}
        if self.oauth is not None:
            return {"Authorization": f"Bearer {self.oauth.access_token()}"}
        return {}

    def _request_headers(self) -> dict:
        headers = dict(self.headers)
        headers.setdefault("User-Agent", USER_AGENT)
        headers.setdefault("Accept-Encoding", "identity")
        for key, value in self._auth_headers().items():
            headers.setdefault(key, value)
        return headers

    def _redact(self, text) -> str:
        secrets_list = _sensitive_header_values(self.headers)
        if self.oauth is not None:
            secrets_list.extend(self.oauth._known_secrets())
        if self.token_env:
            secrets_list.append(os.environ.get(self.token_env, ""))
        return _redact(text, secrets_list)

    def _retry_count(self) -> int:
        return _env_int("JARVIS_MCP_RETRIES", DEFAULT_RETRIES)

    @staticmethod
    def _retry_delay(headers, attempt: int) -> float:
        value = headers.get("Retry-After") if headers else None
        if value:
            try:
                return max(0.0, min(float(value), 5.0))
            except (TypeError, ValueError):
                pass
        return min(2.0, 0.25 * (2 ** attempt))

    def _handle_unauthorized(self) -> None:
        if self.oauth is not None:
            self.oauth.refresh()
            return
        if self.token_env:
            raise MCPError(
                f"MCP server {self.name} rejected the bearer token from "
                f"{self.token_env} (HTTP 401).")
        raise MCPError(
            f"MCP server {self.name} returned HTTP 401. Configure oauth or "
            "a bearer token for this server.")

    def _protocol_headers(self) -> dict:
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self._initialized:
            headers["MCP-Protocol-Version"] = getattr(
                self, "_protocol_version", PROTOCOL_VERSION)
        return headers

    def _rpc(self, method, params=None, timeout=None):
        raise NotImplementedError

    def list_tools(self):
        return _list_all_tools(self._rpc)

    def call_tool(self, name, arguments=None):
        return _call_tool(self._rpc, name, arguments)

    def ping(self):
        return self._rpc("ping", {})


class MCPHTTP(_RemoteMCP):
    """MCP Streamable HTTP (protocol 2025-03-26)."""

    kind = "http"

    def __init__(self, name: str, url: str, headers=None, token_env: str = "",
                 oauth=None, allow_private: bool = False,
                 store: _TokenStore | None = None, timeout: float | None = None):
        super().__init__(name, url, headers, token_env, oauth,
                         allow_private, store, timeout)
        self.session_id = None
        self._initializing = False
        self._protocol_version = PROTOCOL_VERSION

    def start(self):
        with self.lock:
            if self._initialized:
                return self.server_info
            self._handshake()
            return self.server_info

    def _reset_session(self):
        self.session_id = None
        self._initialized = False
        self.server_info = {}

    def _handshake(self):
        if self._initializing:
            raise MCPError(f"MCP server {self.name} is already initializing.")
        self._initializing = True
        try:
            result = self._rpc("initialize", {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "jarvis", "version": "1.0"},
            }, timeout=15)
            self.server_info = result.get("serverInfo", {}) if isinstance(result, dict) else {}
            if isinstance(result, dict) and result.get("protocolVersion"):
                self._protocol_version = str(result["protocolVersion"])
            self._initialized = True
            self._notify("notifications/initialized")
        except Exception:
            self._reset_session()
            raise
        finally:
            self._initializing = False

    def _notify(self, method: str, params=None):
        self._post({"jsonrpc": "2.0", "method": method, "params": params or {}},
                   expect_id=None, timeout=10)

    def _open_post(self, payload: dict, timeout: float):
        data = json.dumps(payload, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
        if len(data) > MAX_REQUEST_BYTES:
            raise MCPError("The MCP request is larger than the 1 MB limit.")
        headers = self._protocol_headers()
        headers.update(self._request_headers())
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return _open_http(self.url, "POST", headers, data,
                          timeout=timeout, allow_private=self.allow_private)

    def _post(self, payload: dict, expect_id=None, timeout=None) -> list[dict]:
        timeout = float(timeout or self.timeout)
        attempts = 0
        auth_retried = False
        session_retried = False
        method = str(payload.get("method") or "")
        while True:
            try:
                response = self._open_post(payload, timeout)
            except _HTTPStatusError as error:
                if error.status == 401:
                    if not auth_retried:
                        auth_retried = True
                        self._handle_unauthorized()
                        continue
                    raise MCPError(
                        f"MCP server {self.name} still rejected the token (HTTP 401).")
                if (error.status == 404 and self.session_id and self._initialized
                        and method != "initialize" and not session_retried
                        and not self._initializing):
                    session_retried = True
                    self._reset_session()
                    self._handshake()
                    continue
                if error.status in (429, 500, 502, 503, 504) and attempts < self._retry_count():
                    delay = self._retry_delay(error.headers, attempts)
                    attempts += 1
                    time.sleep(delay)
                    continue
                detail = self._redact(error.body)[:300]
                raise MCPError(
                    f"MCP server {self.name} returned HTTP {error.status}: {detail}") from None
            except MCPNetworkError:
                if attempts < self._retry_count():
                    time.sleep(self._retry_delay(None, attempts))
                    attempts += 1
                    continue
                raise
            status = getattr(response, "status", 200)
            try:
                session = response.headers.get("Mcp-Session-Id")
                if session:
                    self.session_id = session
                if status in (202, 204):
                    return []
                content_type = str(response.headers.get("Content-Type") or "")
                content_type = content_type.split(";", 1)[0].strip().casefold()
                if content_type == "text/event-stream":
                    if expect_id is None:
                        return []
                    deadline = time.time() + timeout
                    messages = []
                    for _event, data, _event_id in _iter_sse(response, deadline):
                        if not data:
                            continue
                        messages.extend(_messages_from_text(data))
                        message = _response_message(messages, expect_id)
                        if message is not None:
                            return messages
                    raise MCPError(
                        f"MCP server {self.name} closed the stream before the response.")
                body = _read_limited(response, MAX_RESPONSE_BYTES)
                if not body.strip():
                    return []
                return _messages_from_text(body.decode("utf-8", errors="replace"))
            finally:
                try:
                    response.close()
                except Exception:
                    pass

    def _rpc(self, method, params=None, timeout=None):
        with self.lock:
            self._next_id += 1
            request_id = self._next_id
            messages = self._post(
                {"jsonrpc": "2.0", "id": request_id, "method": method,
                 "params": params or {}},
                expect_id=request_id, timeout=timeout)
            message = _response_message(messages, request_id)
            if message is None:
                raise MCPError(
                    f"MCP server {self.name} returned no response for {method}.")
            if "error" in message:
                raise MCPError(self._redact(
                    (message["error"].get("message")
                     if isinstance(message.get("error"), dict)
                     else str(message.get("error"))) or "MCP call failed."))
            return message.get("result", {})

    def close(self):
        with self.lock:
            session = self.session_id
            self._reset_session()
            if not session:
                return
            try:
                headers = self._request_headers()
                headers["Mcp-Session-Id"] = session
                headers["MCP-Protocol-Version"] = PROTOCOL_VERSION
                response = _open_http(self.url, "DELETE", headers, None,
                                      timeout=5, allow_private=self.allow_private)
                response.close()
            except Exception:
                pass


class MCPSSE(_RemoteMCP):
    """Legacy MCP HTTP+SSE transport (protocol 2024-11-05)."""

    kind = "sse"

    def __init__(self, name: str, url: str, headers=None, token_env: str = "",
                 oauth=None, allow_private: bool = False,
                 store: _TokenStore | None = None, timeout: float | None = None):
        super().__init__(name, url, headers, token_env, oauth,
                         allow_private, store, timeout)
        self.endpoint = None
        self._response = None
        self._reader = None
        self._stop = threading.Event()
        self._endpoint_event = threading.Event()
        self._cond = threading.Condition()
        self._pending = {}
        self._stream_error = None

    @property
    def running(self) -> bool:
        return bool(self._initialized and self._stream_error is None
                    and self._reader is not None and self._reader.is_alive())

    def start(self):
        with self.lock:
            if self._initialized and self._stream_error is None:
                return self.server_info
            self._connect()
            try:
                result = self._rpc("initialize", {
                    "protocolVersion": LEGACY_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "jarvis", "version": "1.0"},
                }, timeout=15)
                self.server_info = result.get("serverInfo", {}) if isinstance(result, dict) else {}
                self._initialized = True
                self._notify("notifications/initialized")
            except Exception:
                self._close_stream()
                raise
            return self.server_info

    def _connect(self):
        self._close_stream()
        self._stop.clear()
        self._endpoint_event.clear()
        self._stream_error = None
        self.endpoint = None
        with self._cond:
            self._pending = {}
        headers = self._request_headers()
        headers["Accept"] = "text/event-stream"
        try:
            response = _open_http(self.url, "GET", headers, None,
                                  timeout=max(30.0, self.timeout),
                                  allow_private=self.allow_private)
        except _HTTPStatusError as error:
            if error.status == 401:
                self._handle_unauthorized()
                headers = self._request_headers()
                headers["Accept"] = "text/event-stream"
                response = _open_http(self.url, "GET", headers, None,
                                      timeout=max(30.0, self.timeout),
                                      allow_private=self.allow_private)
            else:
                raise MCPError(
                    f"MCP server {self.name} returned HTTP {error.status}.") from None
        content_type = str(response.headers.get("Content-Type") or "")
        if "text/event-stream" not in content_type.casefold():
            response.close()
            raise MCPError(
                f"MCP server {self.name} did not open an event stream.")
        self._response = response
        self._reader = threading.Thread(
            target=self._read_stream, name=f"mcp-{self.name}-sse", daemon=True)
        self._reader.start()
        if not self._endpoint_event.wait(15):
            self._close_stream()
            raise MCPError(
                f"MCP server {self.name} did not announce an SSE endpoint.")
        if not self.endpoint:
            error = self._stream_error or "no endpoint event"
            self._close_stream()
            raise MCPError(
                f"MCP server {self.name} SSE failed: {self._redact(error)}")

    def _read_stream(self):
        try:
            for event, data, _event_id in _iter_sse(self._response):
                if self._stop.is_set():
                    break
                if event == "endpoint":
                    target = urllib.parse.urljoin(self.url, data.strip())
                    _validate_url(target, self.allow_private, "MCP SSE endpoint")
                    if not _same_origin(target, self.url):
                        raise MCPError("The SSE endpoint is on a different origin.")
                    self.endpoint = target
                    self._endpoint_event.set()
                    continue
                if event not in ("message", "") or not data.strip():
                    continue
                messages = _messages_from_text(data)
                self._dispatch(messages)
        except Exception as error:
            self._stream_error = (
                f"{type(error).__name__}: {error}"
                if not isinstance(error, MCPError) else str(error))
        finally:
            if not self._stop.is_set() and self._stream_error is None:
                self._stream_error = "the SSE stream closed"
            self._endpoint_event.set()
            with self._cond:
                self._cond.notify_all()

    def _dispatch(self, messages):
        with self._cond:
            for message in messages:
                if not isinstance(message, dict):
                    continue
                if "id" in message and "method" not in message:
                    self._pending[message.get("id")] = message
            self._cond.notify_all()

    def _notify(self, method: str, params=None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _send(self, payload: dict, auth_retried: bool = False) -> None:
        if not self.endpoint:
            raise MCPError(f"MCP server {self.name} has no SSE endpoint.")
        data = json.dumps(payload, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
        if len(data) > MAX_REQUEST_BYTES:
            raise MCPError("The MCP request is larger than the 1 MB limit.")
        headers = self._request_headers()
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json, text/event-stream"
        try:
            response = _open_http(self.endpoint, "POST", headers, data,
                                  timeout=self.timeout,
                                  allow_private=self.allow_private)
            try:
                _read_limited(response, 4096, "MCP acknowledgement")
            finally:
                response.close()
        except _HTTPStatusError as error:
            if error.status == 401 and not auth_retried:
                self._handle_unauthorized()
                self._send(payload, auth_retried=True)
                return
            raise MCPError(
                f"MCP server {self.name} rejected a message with HTTP {error.status}.") from None

    def _rpc(self, method, params=None, timeout=None):
        with self.lock:
            timeout = float(timeout or self.timeout)
            if self._stream_error is not None or not self.endpoint:
                self._connect()
            self._next_id += 1
            request_id = self._next_id
            with self._cond:
                self._pending[request_id] = None
            try:
                self._send({"jsonrpc": "2.0", "id": request_id,
                            "method": method, "params": params or {}})
            except Exception:
                with self._cond:
                    self._pending.pop(request_id, None)
                raise
            deadline = time.time() + timeout
            with self._cond:
                while self._pending.get(request_id) is None:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        self._pending.pop(request_id, None)
                        raise MCPError(
                            f"MCP request {method} timed out waiting for the SSE response.")
                    if self._stream_error is not None:
                        self._pending.pop(request_id, None)
                        raise MCPError(
                            f"MCP SSE stream for {self.name} failed: "
                            f"{self._redact(self._stream_error)}")
                    self._cond.wait(min(remaining, 1.0))
                message = self._pending.pop(request_id)
            if "error" in message:
                error = message["error"]
                text = error.get("message") if isinstance(error, dict) else str(error)
                raise MCPError(self._redact(str(text or error)))
            return message.get("result", {})

    def _close_stream(self):
        self._stop.set()
        response, self._response = self._response, None
        _close_now(response)
        reader, self._reader = self._reader, None
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=2)
        with self._cond:
            self._cond.notify_all()

    def close(self):
        with self.lock:
            self._initialized = False
            self.endpoint = None
            self._close_stream()
            with self._cond:
                self._pending = {}


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class MCPManager:
    def __init__(self, path: Path = CONFIG_PATH):
        self.path = Path(path)
        self.servers = {}
        self.lock = threading.RLock()
        self._tokens = _TokenStore(self.path.with_name(TOKEN_FILE_NAME))
        self._config = self._load()
        self._schemas = {}
        self._health = {}

    def _load(self):
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            return []
        if isinstance(payload, dict):
            payload = payload.get("servers", [])
        if not isinstance(payload, list):
            return []
        rows, names = [], set()
        for raw in payload:
            if not isinstance(raw, dict) or not raw.get("enabled", True):
                continue
            name = str(raw.get("name") or "").strip()
            if not name or name in names:
                continue
            transport = str(raw.get("transport") or "").strip().casefold()
            if not transport:
                transport = "stdio" if raw.get("command") else "http"
            transport = transport.replace("-", "_")
            if transport in ("streamable_http", "streamable", "streamablehttp"):
                transport = "http"
            if transport not in ("stdio", "http", "sse"):
                continue
            row = dict(raw)
            row["name"] = name
            row["transport"] = transport
            if transport == "stdio":
                if not raw.get("command"):
                    continue
                row["args"] = [str(item) for item in (raw.get("args") or [])]
                row["env"] = dict(raw.get("env") or {}) if isinstance(raw.get("env"), dict) else {}
                row["cwd"] = raw.get("cwd")
            else:
                if not raw.get("url"):
                    continue
                row["url"] = str(raw["url"])
                row["headers"] = _clean_headers(raw.get("headers"))
                row["token_env"] = str(raw.get("token_env") or "")
                row["allow_private"] = raw.get("allow_private") is True
                oauth = raw.get("oauth")
                if isinstance(oauth, dict):
                    row["oauth"] = dict(oauth)
                elif oauth is True:
                    row["oauth"] = {}
                else:
                    row["oauth"] = None
            rows.append(row)
            names.add(name)
        return rows

    def _spec(self, row):
        if row["transport"] == "stdio":
            return (str(row["command"]), tuple(row.get("args") or []),
                    _freeze(row.get("env") or {}), row.get("cwd"))
        return (row["transport"], str(row["url"]),
                _freeze(row.get("headers") or {}),
                row.get("oauth") is not None,
                _freeze(row.get("oauth") or {}),
                bool(row.get("allow_private")),
                str(row.get("token_env") or ""))

    def reload(self):
        """Re-read mcp.json; stop servers whose name or raw spec changed."""
        with self.lock:
            parsed = self._load()
            specs = {row["name"]: self._spec(row) for row in parsed}
            for name in list(self.servers):
                server = self.servers[name]
                if name not in specs or server.spec != specs[name]:
                    server.close()
                    self.servers.pop(name, None)
                    self._schemas.pop(name, None)
                    self._health.pop(name, None)
            for name in list(self._schemas):
                if name not in specs:
                    self._schemas.pop(name, None)
                    self._health.pop(name, None)
            self._config = parsed

    def _row(self, name):
        return next((item for item in self._config if item["name"] == name), None)

    def _make_server(self, row):
        if row["transport"] == "stdio":
            return MCPProcess(row["name"], row["command"], row.get("args"),
                              row.get("env"), row.get("cwd"))
        if row["transport"] == "sse":
            return MCPSSE(row["name"], row["url"], row.get("headers"),
                          row.get("token_env"), row.get("oauth"),
                          row.get("allow_private"), self._tokens)
        return MCPHTTP(row["name"], row["url"], row.get("headers"),
                       row.get("token_env"), row.get("oauth"),
                       row.get("allow_private"), self._tokens)

    def _server(self, name):
        row = self._row(name)
        if row is None:
            raise MCPError(f"Unknown MCP server: {name}")
        with self.lock:
            server = self.servers.get(name)
            if server is None:
                server = self._make_server(row)
                server.spec = self._spec(row)
                self.servers[name] = server
            server.start()
            return server

    def _cooldown_seconds(self, name) -> float:
        state = self._health.get(name) or {}
        try:
            return max(0.0, float(state.get("cooldown_until") or 0) - time.time())
        except (TypeError, ValueError):
            return 0.0

    def _cooldown_check(self, name):
        remaining = self._cooldown_seconds(name)
        if remaining > 0:
            last_error = (self._health.get(name) or {}).get("last_error") or ""
            raise MCPError(
                f"MCP server {name} is cooling down for {int(remaining) + 1}s"
                + (f" after: {last_error}" if last_error else "."))

    def _record_failure(self, name, error):
        state = self._health.setdefault(
            name, {"failures": 0, "cooldown_until": 0.0, "last_error": ""})
        if isinstance(error, MCPAuthRequired):
            # Do not hammer a server that will keep returning 401. A short
            # cooldown also gives the user time to run the auth command.
            base = _env_float("JARVIS_MCP_COOLDOWN_SECONDS", DEFAULT_COOLDOWN)
            state["last_error"] = self._redact_error(name, error)[:300]
            state["cooldown_until"] = time.time() + base if base else 0.0
            return
        state["failures"] = int(state.get("failures") or 0) + 1
        base = _env_float("JARVIS_MCP_COOLDOWN_SECONDS", DEFAULT_COOLDOWN)
        delay = min(300.0, base * (2 ** min(state["failures"] - 1, 5))) if base else 0.0
        state["cooldown_until"] = time.time() + delay
        state["last_error"] = self._redact_error(name, error)[:300]

    def _record_success(self, name):
        self._health[name] = {"failures": 0, "cooldown_until": 0.0, "last_error": ""}

    def _redact_error(self, name, error) -> str:
        text = str(error)
        row = self._row(name) or {}
        secrets_list = _sensitive_header_values(row.get("headers") or {})
        if row.get("token_env"):
            secrets_list.append(os.environ.get(row["token_env"], ""))
        record = self._tokens.get(name) or {}
        secrets_list.extend([record.get("access_token"), record.get("refresh_token"),
                             record.get("client_secret")])
        return _redact(text, secrets_list)

    def _auth_state(self, row) -> str:
        if row["transport"] == "stdio" or row.get("oauth") is None:
            return "not_configured"
        record = self._tokens.get(row["name"])
        if not isinstance(record, dict) or not _same_resource(record.get("resource"), row["url"]):
            return "required"
        try:
            expires = float(record.get("expires_at") or 0)
        except (TypeError, ValueError):
            expires = 0.0
        if record.get("access_token") and (not expires or expires > time.time() + 30):
            return "authorized"
        if record.get("refresh_token") and record.get("token_endpoint"):
            return "refreshable"
        return "expired"

    def config(self):
        output = []
        for row in self._config:
            if row["transport"] == "stdio":
                output.append({"name": row["name"], "transport": "stdio",
                               "command": row["command"],
                               "args": row.get("args", [])})
                continue
            output.append({
                "name": row["name"],
                "transport": row["transport"],
                "url": _safe_url(row["url"]),
                "headers": sorted(row.get("headers") or {}),
                "oauth": row.get("oauth") is not None,
                "allow_private": bool(row.get("allow_private")),
                "token_env": row.get("token_env") or "",
            })
        return output

    def status(self):
        output = []
        for row in self._config:
            name = row["name"]
            server = self.servers.get(name)
            cooldown = self._cooldown_seconds(name)
            state = self._health.get(name) or {}
            output.append({
                "name": name,
                "transport": row["transport"],
                "running": bool(server and server.running),
                "tools": len((self._schemas.get(name) or {}).get("tools") or []),
                "cooldown_seconds": round(cooldown, 1),
                "last_error": state.get("last_error") or "",
                "auth": self._auth_state(row),
                **({"url": _safe_url(row["url"])} if row["transport"] != "stdio" else {}),
            })
        return output

    def tools(self, force: bool = False):
        self.reload()
        ttl = _env_float("JARVIS_MCP_SCHEMA_TTL", DEFAULT_SCHEMA_TTL)
        output = []
        for row in self._config:
            name = row["name"]
            cache = self._schemas.get(name)
            if (cache and not force and ttl > 0
                    and time.time() - float(cache.get("at") or 0) < ttl):
                output.extend(cache.get("tools") or [])
                continue
            cooldown = self._cooldown_seconds(name)
            if cooldown > 0:
                message = ((self._health.get(name) or {}).get("last_error")
                           or f"cooling down for {int(cooldown) + 1}s")
                if cache and cache.get("tools"):
                    output.extend({**tool, "stale": True, "error": message}
                                  for tool in cache["tools"])
                else:
                    output.append({"server": name, "error": message})
                continue
            try:
                listing = self._server(name).list_tools()
                tools = [{"server": name, "name": tool.get("name"),
                          "description": tool.get("description", ""),
                          "input_schema": tool.get("inputSchema", {})}
                         for tool in listing]
                self._schemas[name] = {"at": time.time(), "tools": tools}
                self._record_success(name)
                output.extend(tools)
            except Exception as error:
                self._record_failure(name, error)
                message = self._redact_error(name, error)[:300]
                if cache and cache.get("tools"):
                    output.extend({**tool, "stale": True, "error": message}
                                  for tool in cache["tools"])
                else:
                    output.append({"server": name, "error": message})
        return output

    def call(self, server, tool, arguments=None):
        with self.lock:
            row = self._row(server)
            if row is None:
                raise MCPError(f"Unknown MCP server: {server}")
            self._cooldown_check(server)
            try:
                result = self._server(server).call_tool(tool, arguments)
                self._record_success(server)
                return {"server": server, "tool": tool, "result": result}
            except Exception as error:
                self._record_failure(server, error)
                raise

    def ping(self, name):
        with self.lock:
            if self._row(name) is None:
                raise MCPError(f"Unknown MCP server: {name}")
            self._cooldown_check(name)
            try:
                result = self._server(name).ping()
                self._record_success(name)
                return {"server": name, "ok": True, "result": result}
            except Exception as error:
                self._record_failure(name, error)
                raise

    def authorize(self, name, open_browser: bool = True, notify=None):
        self.reload()
        row = self._row(name)
        if row is None:
            raise MCPError(f"Unknown MCP server: {name}")
        if row["transport"] == "stdio":
            raise MCPError("Only remote MCP servers use OAuth.")
        if row.get("oauth") is None:
            raise MCPError(
                f'MCP server {name} is not configured for OAuth; add "oauth": true '
                "to its mcp.json entry.")
        client = _OAuthClient(name, row["url"], row.get("oauth"),
                              row.get("allow_private"), self._tokens)
        result = client.authorize(open_browser=open_browser, notify=notify)
        with self.lock:
            server = self.servers.pop(name, None)
            if server is not None:
                server.close()
            self._health.pop(name, None)
        return result

    def logout(self, name):
        self.reload()
        if self._row(name) is None:
            raise MCPError(f"Unknown MCP server: {name}")
        self._tokens.delete(name)
        with self.lock:
            server = self.servers.pop(name, None)
            if server is not None:
                server.close()
            self._health.pop(name, None)
        return {"server": name, "logged_out": True}

    def close(self):
        with self.lock:
            for server in self.servers.values():
                server.close()
            self.servers = {}


# ---------------------------------------------------------------------------
# CLI: python3 mcp_client.py auth|logout|status [--config PATH]
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="Jarvis MCP remote OAuth helper")
    parser.add_argument("--config", default=str(CONFIG_PATH),
                        help="path to mcp.json")
    commands = parser.add_subparsers(dest="command", required=True)
    auth = commands.add_parser("auth", help="authorize a remote MCP server")
    auth.add_argument("server")
    auth.add_argument("--no-browser", action="store_true",
                      help="print the URL instead of opening a browser")
    logout = commands.add_parser("logout", help="delete a server's stored tokens")
    logout.add_argument("server")
    commands.add_parser("status", help="print server status as JSON")
    args = parser.parse_args(argv)

    manager = MCPManager(Path(args.config).expanduser())
    try:
        if args.command == "auth":
            def notice(url):
                print("Open this URL to authorize Jarvis:\n" + url,
                      file=sys.stderr, flush=True)

            result = manager.authorize(
                args.server, open_browser=not args.no_browser, notify=notice)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif args.command == "logout":
            print(json.dumps(manager.logout(args.server), ensure_ascii=False, indent=2))
        else:
            print(json.dumps(manager.status(), ensure_ascii=False, indent=2))
    except MCPError as error:
        print(f"mcp: {error}", file=sys.stderr)
        return 1
    finally:
        manager.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
