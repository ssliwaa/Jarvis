"""Remote MCP transports, OAuth and manager health contracts."""
import http.server
import json
import os
import queue
import stat
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from pathlib import Path
from unittest import mock

import mcp_client


class _FakeMCP:
    """Tiny local server implementing streamable HTTP, legacy SSE and OAuth."""

    def __init__(self, *, sse_response=False, legacy=False, require_auth=False,
                 expected_token="static-token", fail_count=0):
        self.sse_response = bool(sse_response)
        self.legacy = bool(legacy)
        self.require_auth = bool(require_auth)
        self.expected_token = expected_token
        self.fail_count = int(fail_count)
        self.requests = []
        self.list_count = 0
        self.token_requests = []
        self.registration_requests = []
        self.legacy_queue = queue.Queue()
        self.stop = threading.Event()
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def _send_json(self, status, value, headers=None):
                body = json.dumps(value, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self):
                if not fake.require_auth:
                    return True
                return self.headers.get("Authorization") == f"Bearer {fake.expected_token}"

            def _rpc_result(self, message):
                method = message.get("method")
                params = message.get("params") or {}
                if method == "initialize":
                    return {"protocolVersion": "2025-03-26",
                            "serverInfo": {"name": "fake", "version": "1"}}
                if method == "tools/list":
                    fake.list_count += 1
                    return {"tools": [{
                        "name": "echo", "description": "Echo text",
                        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
                    }]}
                if method == "tools/call":
                    arguments = params.get("arguments") or {}
                    return {"content": [{"type": "text", "text": arguments.get("text", "")}]}
                if method == "ping":
                    return {}
                return None

            def _reply(self, message):
                request_id = message.get("id")
                if request_id is None:
                    return None
                result = self._rpc_result(message)
                if result is None:
                    return {"jsonrpc": "2.0", "id": request_id,
                            "error": {"code": -32601, "message": "unknown method"}}
                return {"jsonrpc": "2.0", "id": request_id, "result": result}

            def do_GET(self):
                parsed = urllib.parse.urlsplit(self.path)
                if parsed.path.startswith("/.well-known/oauth-protected-resource"):
                    self._send_json(200, {"authorization_servers": [fake.base]})
                    return
                if parsed.path.startswith("/.well-known/oauth-authorization-server"):
                    self._send_json(200, {
                        "issuer": fake.base,
                        "authorization_endpoint": fake.base + "/authorize",
                        "token_endpoint": fake.base + "/token",
                        "registration_endpoint": fake.base + "/register",
                    })
                    return
                if parsed.path == "/sse":
                    if not self._authorized():
                        self.send_response(401)
                        self.end_headers()
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    try:
                        self.wfile.write(b"event: endpoint\ndata: /messages\n\n")
                        self.wfile.flush()
                        while not fake.stop.is_set():
                            try:
                                message = fake.legacy_queue.get(timeout=0.2)
                            except queue.Empty:
                                continue
                            payload = json.dumps(message, ensure_ascii=False)
                            self.wfile.write(
                                f"event: message\ndata: {payload}\n\n".encode("utf-8"))
                            self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        pass
                    return
                self.send_error(404)

            def do_POST(self):
                parsed = urllib.parse.urlsplit(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                if parsed.path == "/token":
                    form = dict(urllib.parse.parse_qsl(raw.decode("utf-8")))
                    fake.token_requests.append(form)
                    if form.get("grant_type") == "refresh_token":
                        if form.get("refresh_token") != "refresh-1":
                            self._send_json(400, {"error": "invalid_grant"})
                            return
                        self._send_json(200, {
                            "access_token": "fresh-token", "token_type": "Bearer",
                            "expires_in": 3600, "refresh_token": "next-refresh",
                        })
                        return
                    if form.get("grant_type") == "authorization_code":
                        if not form.get("code_verifier") or form.get("code") != "abc":
                            self._send_json(400, {"error": "invalid_grant"})
                            return
                        self._send_json(200, {
                            "access_token": "authorized-token", "token_type": "Bearer",
                            "expires_in": 3600, "refresh_token": "authorized-refresh",
                        })
                        return
                    self._send_json(400, {"error": "unsupported_grant_type"})
                    return
                if parsed.path == "/register":
                    value = json.loads(raw.decode("utf-8"))
                    fake.registration_requests.append(value)
                    self._send_json(201, {
                        "client_id": "registered-client",
                        "token_endpoint_auth_method": "none",
                    })
                    return
                if not self._authorized():
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Bearer error="invalid_token"')
                    self.end_headers()
                    return
                if fake.fail_count > 0:
                    fake.fail_count -= 1
                    body = json.dumps({
                        "error": "upstream rejected " + self.headers.get("X-Api-Key", "")
                    }).encode("utf-8")
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                try:
                    message = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeError):
                    self.send_response(400)
                    self.end_headers()
                    return
                fake.requests.append({"path": parsed.path,
                                      "headers": dict(self.headers),
                                      "message": message})
                if parsed.path == "/messages":
                    reply = self._reply(message)
                    if reply is not None:
                        fake.legacy_queue.put(reply)
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if parsed.path not in ("/mcp", "/mcp-sse"):
                    self.send_error(404)
                    return
                method = message.get("method")
                if method == "initialize":
                    session = {"Mcp-Session-Id": "sess-1"}
                else:
                    session = None
                    if method != "notifications/initialized" \
                            and self.headers.get("Mcp-Session-Id") != "sess-1":
                        self.send_response(404)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                reply = self._reply(message)
                if reply is None:
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if fake.sse_response:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    for key, value in (session or {}).items():
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(
                        f"event: message\ndata: {json.dumps(reply)}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    return
                headers = dict(session or {})
                self._send_json(200, reply, headers)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02},
            daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        self.legacy_queue.put({})
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


def _config(root: Path, url: str, **extra) -> Path:
    row = {"name": "remote", "transport": "http", "url": url,
           "allow_private": True}
    row.update(extra)
    path = root / "mcp.json"
    path.write_text(json.dumps({"servers": [row]}), encoding="utf-8")
    return path


class RemoteMCPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.close()
        self.tmp.cleanup()

    def _server(self, **kwargs):
        server = _FakeMCP(**kwargs)
        self.servers.append(server)
        return server

    def test_streamable_http_json_tools_and_call(self):
        server = self._server()
        manager = mcp_client.MCPManager(_config(self.root, server.base + "/mcp"))
        try:
            tools = manager.tools()
            self.assertEqual(tools[0]["name"], "echo")
            result = manager.call("remote", "echo", {"text": "hello"})
            self.assertEqual(result["result"]["content"][0]["text"], "hello")
            self.assertTrue(manager.status()[0]["running"])
            self.assertTrue(all(item["headers"].get("Mcp-Session-Id") == "sess-1"
                                for item in server.requests[1:]))
            self.assertIn("text/event-stream", server.requests[0]["headers"]["Accept"])
            self.assertEqual(server.requests[0]["message"]["params"]["protocolVersion"],
                             mcp_client.PROTOCOL_VERSION)
            headers = {key.lower(): value
                       for key, value in server.requests[2]["headers"].items()}
            self.assertEqual(headers.get("mcp-protocol-version"),
                             mcp_client.PROTOCOL_VERSION)
            pong = manager.ping("remote")
            self.assertTrue(pong["ok"])
        finally:
            manager.close()

    def test_streamable_http_event_stream_reply(self):
        server = self._server(sse_response=True)
        manager = mcp_client.MCPManager(_config(self.root, server.base + "/mcp-sse"))
        try:
            tools = manager.tools()
            self.assertEqual(tools[0]["name"], "echo")
            result = manager.call("remote", "echo", {"text": "streamed"})
            self.assertEqual(result["result"]["content"][0]["text"], "streamed")
        finally:
            manager.close()

    def test_legacy_sse_transport(self):
        server = self._server(legacy=True)
        manager = mcp_client.MCPManager(
            _config(self.root, server.base + "/sse", transport="sse"))
        try:
            tools = manager.tools()
            self.assertEqual(tools[0]["name"], "echo")
            result = manager.call("remote", "echo", {"text": "legacy"})
            self.assertEqual(result["result"]["content"][0]["text"], "legacy")
            self.assertEqual(server.requests[0]["message"]["params"]["protocolVersion"],
                             mcp_client.LEGACY_PROTOCOL_VERSION)
        finally:
            manager.close()

    def test_private_target_requires_explicit_opt_in(self):
        server = self._server()
        path = _config(self.root, server.base + "/mcp", allow_private=False)
        manager = mcp_client.MCPManager(path)
        try:
            tools = manager.tools()
            self.assertEqual(len(tools), 1)
            self.assertIn("error", tools[0])
            self.assertIn("HTTPS", tools[0]["error"])
            self.assertEqual(server.requests, [])
        finally:
            manager.close()

    def test_schema_cache_is_used_until_forced(self):
        server = self._server()
        manager = mcp_client.MCPManager(_config(self.root, server.base + "/mcp"))
        try:
            manager.tools()
            manager.tools()
            self.assertEqual(server.list_count, 1)
            manager.tools(force=True)
            self.assertEqual(server.list_count, 2)
        finally:
            manager.close()

    def test_cooldown_stops_repeated_failures(self):
        server = self._server(fail_count=1)
        manager = mcp_client.MCPManager(_config(self.root, server.base + "/mcp"))
        try:
            with mock.patch.dict(os.environ, {
                    "JARVIS_MCP_RETRIES": "0",
                    "JARVIS_MCP_COOLDOWN_SECONDS": "30"}):
                first = manager.tools()
                self.assertIn("error", first[0])
                requests_after_failure = len(server.requests)
                second = manager.tools()
                self.assertIn("error", second[0])
                self.assertEqual(len(server.requests), requests_after_failure)
                self.assertGreater(manager.status()[0]["cooldown_seconds"], 0)
        finally:
            manager.close()

    def test_bearer_token_from_environment(self):
        server = self._server(require_auth=True, expected_token="env-token")
        manager = mcp_client.MCPManager(_config(
            self.root, server.base + "/mcp", token_env="TEST_MCP_TOKEN"))
        try:
            with mock.patch.dict(os.environ, {"TEST_MCP_TOKEN": "env-token"}):
                tools = manager.tools()
                self.assertEqual(tools[0]["name"], "echo")
            config = manager.config()[0]
            self.assertNotIn("env-token", json.dumps(config))
        finally:
            manager.close()

    def test_oauth_refresh_and_private_token_file(self):
        server = self._server(require_auth=True, expected_token="fresh-token")
        config_path = _config(self.root, server.base + "/mcp", oauth=True)
        token_path = self.root / mcp_client.TOKEN_FILE_NAME
        token_path.write_text(json.dumps({"version": 1, "servers": {"remote": {
            "resource": server.base + "/mcp",
            "access_token": "expired-token",
            "expires_at": 0,
            "refresh_token": "refresh-1",
            "token_endpoint": server.base + "/token",
            "client_id": "client-1",
            "token_endpoint_auth_method": "none",
        }}}), encoding="utf-8")
        manager = mcp_client.MCPManager(config_path)
        try:
            tools = manager.tools()
            self.assertEqual(tools[0]["name"], "echo")
            self.assertEqual(server.token_requests[0]["grant_type"], "refresh_token")
            stored = json.loads(token_path.read_text(encoding="utf-8"))["servers"]["remote"]
            self.assertEqual(stored["access_token"], "fresh-token")
            self.assertEqual(stat.S_IMODE(token_path.stat().st_mode), 0o600)
            self.assertEqual(manager.status()[0]["auth"], "authorized")
            self.assertNotIn("fresh-token", json.dumps(manager.status()))
            self.assertNotIn("fresh-token", json.dumps(manager.config()))
        finally:
            manager.close()

    def test_oauth_authorization_code_flow(self):
        server = self._server()
        config_path = _config(self.root, server.base + "/mcp", oauth={
            "client_id": "client-1",
            "authorization_endpoint": server.base + "/authorize",
            "token_endpoint": server.base + "/token",
        })
        manager = mcp_client.MCPManager(config_path)
        captured = {}
        result_holder = {}

        def notify(url):
            captured["url"] = url

        def run():
            result_holder["result"] = manager.authorize(
                "remote", open_browser=False, notify=notify)

        thread = threading.Thread(target=run)
        try:
            thread.start()
            deadline = time.time() + 5
            while "url" not in captured and time.time() < deadline:
                time.sleep(0.01)
            self.assertIn("url", captured)
            parsed = urllib.parse.urlsplit(captured["url"])
            query = dict(urllib.parse.parse_qsl(parsed.query))
            self.assertEqual(query["code_challenge_method"], "S256")
            self.assertTrue(query["code_challenge"])
            redirect = query["redirect_uri"]
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(
                    redirect + "?code=abc&state=" + urllib.parse.quote(query["state"]),
                    timeout=5) as response:
                self.assertEqual(response.status, 200)
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertTrue(result_holder["result"]["authorized"])
            form = server.token_requests[0]
            self.assertTrue(form["code_verifier"])
            self.assertEqual(form["resource"], server.base + "/mcp")
            stored = json.loads((self.root / mcp_client.TOKEN_FILE_NAME).read_text())
            self.assertEqual(stored["servers"]["remote"]["access_token"],
                             "authorized-token")
        finally:
            if thread.is_alive():
                thread.join(timeout=1)
            manager.close()

    def test_oauth_discovery_and_registration(self):
        server = self._server()
        manager = mcp_client.MCPManager(_config(
            self.root, server.base + "/mcp", oauth=True))
        try:
            client = mcp_client._OAuthClient(
                "remote", server.base + "/mcp", {},
                True, manager._tokens)
            metadata = client.discover()
            self.assertEqual(metadata["token_endpoint"], server.base + "/token")
            callback = mcp_client._CallbackServer()
            try:
                registered = client._register(
                    metadata["registration_endpoint"], callback.redirect_uri)
            finally:
                callback.close()
            self.assertEqual(registered["client_id"], "registered-client")
        finally:
            manager.close()

    def test_header_secret_is_redacted_from_server_errors(self):
        server = self._server(fail_count=1)
        secret = "header-secret-value"
        manager = mcp_client.MCPManager(_config(
            self.root, server.base + "/mcp", headers={"X-Api-Key": secret}))
        try:
            with mock.patch.dict(os.environ, {
                    "JARVIS_MCP_RETRIES": "0",
                    "JARVIS_MCP_COOLDOWN_SECONDS": "0"}):
                tools = manager.tools()
            self.assertIn("error", tools[0])
            self.assertNotIn(secret, tools[0]["error"])
        finally:
            manager.close()

    def test_logout_removes_tokens(self):
        server = self._server(require_auth=True, expected_token="fresh-token")
        config_path = _config(self.root, server.base + "/mcp", oauth=True)
        token_path = self.root / mcp_client.TOKEN_FILE_NAME
        token_path.write_text(json.dumps({"version": 1, "servers": {"remote": {
            "resource": server.base + "/mcp",
            "access_token": "fresh-token",
            "expires_at": time.time() + 3600,
            "token_endpoint": server.base + "/token",
            "client_id": "client-1",
        }}}), encoding="utf-8")
        manager = mcp_client.MCPManager(config_path)
        try:
            self.assertEqual(manager.status()[0]["auth"], "authorized")
            self.assertTrue(manager.logout("remote")["logged_out"])
            self.assertEqual(manager.status()[0]["auth"], "required")
            stored = json.loads(token_path.read_text(encoding="utf-8"))
            self.assertNotIn("remote", stored.get("servers", {}))
        finally:
            manager.close()

    def test_config_never_returns_header_values(self):
        server = self._server()
        manager = mcp_client.MCPManager(_config(
            self.root, server.base + "/mcp",
            headers={"X-Api-Key": "top-secret", "Authorization": "Bearer static"}))
        try:
            rendered = json.dumps(manager.config())
            self.assertNotIn("top-secret", rendered)
            self.assertNotIn("Bearer static", rendered)
            self.assertIn("X-Api-Key", rendered)
        finally:
            manager.close()


if __name__ == "__main__":
    unittest.main()
