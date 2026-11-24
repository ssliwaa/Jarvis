"""Remote MCP Face: state credentials, OAuth scopes/PKCE, rate limiting,
Streamable HTTP transport and the owner CLI -- on a real loopback server."""
import base64
import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase, mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import jarvis_mcp_http as face

STATE_PATH = Path(tempfile.mkdtemp()) / "mcp-http.json"
URL_FILE = Path(tempfile.mkdtemp()) / "pub-url.txt"
PASSPHRASE = "fraza-zgody-tajna"
SALT = "salt123"
SEED = {"client_id": "cid-1", "client_secret": "csec-1", "salt": SALT,
        "passphrase_hash": face._hash(PASSPHRASE, SALT), "refresh": {}}
GLOBAL_MAPS = ("ACCESS", "SESSIONS", "CODES", "RATE")


def seed_state(extra=None):
    data = dict(SEED)
    data.update(extra or {})
    STATE_PATH.write_text(json.dumps(data), encoding="utf-8")


def install_face_patches():
    return [mock.patch.object(face, "STATE_PATH", STATE_PATH),
            mock.patch.object(face, "URL_FILE", URL_FILE),
            mock.patch.object(face, "PUBLIC_URL_ENV", "")]


class _FaceCase(TestCase):
    """Common tmp state, URL file resets and global-map save/restore."""

    def setUp(self):
        seed_state()
        self.patchers = install_face_patches()
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self._saved = {name: dict(getattr(face, name)) for name in GLOBAL_MAPS}
        for name in GLOBAL_MAPS:
            getattr(face, name).clear()
        self._cache = dict(face._URL_CACHE)
        face._URL_CACHE.clear()
        self._url_file_content = URL_FILE.read_text(encoding="utf-8") if URL_FILE.exists() else None
        if URL_FILE.exists():
            URL_FILE.unlink()
        self._env = {k: os.environ.pop(k, None) for k in ("JARVIS_MCP_PASSPHRASE",
                                                          "JARVIS_MCP_PUBLIC_URL")}
        os.environ.pop("JARVIS_MCP_HTTP_ANON", None)
        self.addCleanup(self._restore_globals)

    def _restore_globals(self):
        for name in GLOBAL_MAPS:
            getattr(face, name).clear()
            getattr(face, name).update(self._saved[name])
        face._URL_CACHE.clear()
        face._URL_CACHE.update(self._cache)
        for key, value in self._env.items():
            if value is not None:
                os.environ[key] = value
        if self._url_file_content is None:
            if URL_FILE.exists():
                URL_FILE.unlink()
        else:
            URL_FILE.write_text(self._url_file_content, encoding="utf-8")


class StateAndUrlTests(_FaceCase):
    def test_load_state_seeds_missing_fields_and_persists(self):
        empty = Path(tempfile.mkdtemp()) / "fresh.json"
        with mock.patch.object(face, "STATE_PATH", empty), \
                mock.patch.dict(os.environ, {"JARVIS_MCP_PASSPHRASE": "seed-phrase-123"}):
            state = face.load_state()
        self.assertTrue(state["client_id"].startswith("jarvis-"))
        self.assertEqual(len(state["client_secret"]), 43)
        self.assertEqual(len(state["salt"]), 32)
        self.assertEqual(state["passphrase_hash"], face._hash("seed-phrase-123", state["salt"]))
        self.assertTrue(state["passphrase_generated"])
        self.assertEqual(state["refresh"], {})
        self.assertEqual(json.loads(empty.read_text(encoding="utf-8")), state)
        self.assertEqual(oct(empty.stat().st_mode & 0o777), "0o600")

    def test_load_state_is_stable_and_rebuilds_corrupt_files(self):
        first = face.load_state()
        self.assertEqual(first, SEED)
        corrupt = Path(tempfile.mkdtemp()) / "corr.json"
        corrupt.write_text("{corrupt", encoding="utf-8")
        with mock.patch.object(face, "STATE_PATH", corrupt):
            rebuilt = face.load_state()
        self.assertEqual(sorted(rebuilt),
                         ["client_id", "client_secret", "passphrase_generated",
                          "passphrase_hash", "refresh", "salt"])
        corrupt.write_text("[1, 2]", encoding="utf-8")
        with mock.patch.object(face, "STATE_PATH", corrupt):
            again = face.load_state()
        self.assertIsInstance(again["refresh"], dict)

    def test_public_url_priority_env_file_and_fallback(self):
        self.assertFalse(URL_FILE.exists())
        face._URL_CACHE.clear()
        self.assertEqual(face.public_url(), "http://127.0.0.1:4711")
        URL_FILE.write_text("https://pub.example/", encoding="utf-8")
        face._URL_CACHE.clear()
        self.assertEqual(face.public_url(), "https://pub.example")
        self.assertEqual(face.public_url(), "https://pub.example")  # teraz z cache
        with mock.patch.object(face, "PUBLIC_URL_ENV", "https://env.example"):
            self.assertEqual(face.public_url(), "https://env.example")
        URL_FILE.unlink()
        face._URL_CACHE.clear()
        self.assertEqual(face.public_url(), "http://127.0.0.1:4711")
        URL_FILE.write_text("nothttp", encoding="utf-8")
        face._URL_CACHE.clear()
        self.assertEqual(face.public_url(), "http://127.0.0.1:4711")

    def test_save_state_is_atomic_and_private(self):
        data = dict(SEED)
        face.save_state(data)
        self.assertEqual(json.loads(STATE_PATH.read_text(encoding="utf-8")), data)
        self.assertEqual(oct(STATE_PATH.stat().st_mode & 0o777), "0o600")
        leftovers = list(STATE_PATH.parent.glob(".mcp-http.json-*"))
        self.assertEqual(leftovers, [])


class TokensAndLimitsTests(_FaceCase):
    def test_passphrase_hash_and_check(self):
        state = face.load_state()
        self.assertTrue(face.passphrase_ok(state, PASSPHRASE))
        self.assertFalse(face.passphrase_ok(state, ""))
        self.assertFalse(face.passphrase_ok(state, "zla-fraza"))

    def test_rate_limit_window(self):
        self.assertTrue(all(face.rate_ok("9.9.9.9") for _ in range(90)))
        self.assertFalse(face.rate_ok("9.9.9.9"))
        face.RATE["1.1.1.1"] = [time.time() - 120.0] * 90
        self.assertTrue(face.rate_ok("1.1.1.1"))

    def test_issue_access_and_refresh_rotation(self):
        token, ttl = face.issue_access("jarvis.admin")
        self.assertTrue(token.startswith("jmt_"))
        self.assertEqual(ttl, 28800)
        self.assertEqual(face.ACCESS[token]["scope"], "jarvis.admin")
        seed_state({"refresh": {"jmr_old": {"expires": time.time() - 1,
                                            "scope": "jarvis.read"}}})
        state = face.load_state()
        refresh = face.issue_refresh("jarvis.read", state)
        self.assertTrue(refresh.startswith("jmr_"))
        self.assertIn(refresh, state["refresh"])
        self.assertNotIn("jmr_old", state["refresh"])
        stored = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        self.assertIn(refresh, stored["refresh"])

    def test_token_scope_matrix(self):
        with mock.patch.object(face, "ANON", False):
            self.assertEqual(face.token_scope(""), "")
            self.assertEqual(face.token_scope("Bearer"), "")
            self.assertEqual(face.token_scope("Basic xyz"), "")
            token, _ = face.issue_access("jarvis.read")
            self.assertEqual(face.token_scope("bearer " + token), "jarvis.read")
            face.ACCESS[token]["expires"] = time.time() - 1
            self.assertEqual(face.token_scope("Bearer " + token), "")
        with mock.patch.object(face, "ANON", True):
            self.assertEqual(face.token_scope(""), "jarvis.read")

    def test_scope_guard_matrix(self):
        read_call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "ask", "arguments": {"question": "q"}}}
        write_call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "remember", "arguments": {"text": "x"}}}
        self.assertIsNone(face._scope_guard({"method": "tools/list"}, {"jarvis.read"}))
        self.assertIsNone(face._scope_guard(read_call, {"jarvis.read"}))
        self.assertIsNone(face._scope_guard(write_call, {"jarvis.admin"}))
        self.assertIsNone(face._scope_guard({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                             "params": {"name": "nope"}}, {"jarvis.read"}))
        denied = face._scope_guard(write_call, {"jarvis.read"})
        self.assertEqual(denied["id"], 2)
        self.assertTrue(denied["result"]["isError"])
        self.assertEqual(denied["result"]["content"][0]["text"],
                         "This token carries only jarvis.read; that tool writes or "
                         "controls the machine. Re-consent with the jarvis.admin scope.")
        self.assertNotIn("structuredContent", denied["result"])

    def test_metadata_protected_and_sse_frame(self):
        meta = face.metadata()
        base = "http://127.0.0.1:4711"
        self.assertEqual(meta["issuer"], base)
        self.assertEqual(meta["authorization_endpoint"], base + "/authorize")
        self.assertEqual(meta["token_endpoint"], base + "/token")
        self.assertEqual(meta["grant_types_supported"], ["authorization_code", "refresh_token"])
        self.assertEqual(meta["code_challenge_methods_supported"], ["S256", "plain"])
        self.assertEqual(meta["scopes_supported"], ["jarvis.read", "jarvis.admin"])
        protected = face.protected_resource()
        self.assertEqual(protected["resource"], base + "/mcp")
        self.assertEqual(protected["bearer_methods_supported"], ["header"])
        self.assertEqual(face.sse_frame('{"a": 1}'),
                         b'event: message\ndata: {"a": 1}\n\n')


class _ServerCase(_FaceCase):
    """Real ThreadingHTTPServer on 127.0.0.1:0 sharing the patched face."""

    @classmethod
    def setUpClass(cls):
        cls._class_server = ThreadingHTTPServer(("127.0.0.1", 0), face.Handler)
        cls.port = cls._class_server.server_address[1]
        cls._class_thread = threading.Thread(target=cls._class_server.serve_forever, daemon=True)
        cls._class_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls._class_server.shutdown()
        cls._class_server.server_close()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.__class__.port}"

    def _open(self):
        return urllib.request.build_opener(_NoRedirect())

    def _request(self, path, *, method="GET", data=None, headers=None):
        extra = dict(headers or {})
        if data is not None:
            extra.setdefault("Content-Type", "application/json")
        body = data.encode() if isinstance(data, str) else data
        request = urllib.request.Request(self.base + path, data=body, headers=extra, method=method)
        with self._open().open(request, timeout=5) as response:
            return response.status, dict(response.headers), response.read()

    def _request_error(self, path, *, method="GET", data=None, headers=None):
        extra = dict(headers or {})
        if data is not None:
            extra.setdefault("Content-Type", "application/json")
        body = data.encode() if isinstance(data, str) else data
        request = urllib.request.Request(self.base + path, data=body, headers=extra, method=method)
        opener = self._open()
        try:
            with opener.open(request, timeout=5) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers), error.read()

    def _form_post(self, path, form, headers=None):
        data = urllib.parse.urlencode(form).encode()
        return self._request_error(path, method="POST", data=data,
                                   headers={"Content-Type": "application/x-www-form-urlencoded",
                                            **(headers or {})})

    def _json_post(self, path, payload, headers=None):
        return self._request_error(path, method="POST", data=json.dumps(payload).encode(),
                                   headers={"Content-Type": "application/json", **(headers or {})})

    def _token_exchange(self, form, basic=None):
        headers = {}
        if basic:
            headers["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode()
        return self._form_post("/token", form, headers=headers)

    def _grant_code(self, *, redirect_uri="https://cb/cb", **extra):
        form = {"passphrase": PASSPHRASE, "client_id": "cid-1", "redirect_uri": redirect_uri}
        form.update(extra)
        status, headers, _ = self._form_post("/authorize", form)
        self.assertEqual(status, 302)
        location = headers.get("Location", "")
        return location.split("code=")[1].split("&")[0], location


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpBasicsTests(_ServerCase):
    def test_healthz_wellknowns_and_errors(self):
        status, headers, raw = self._request("/healthz")
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertEqual(body, {"ok": True, "tools": 12,
                                "transport": "streamable-http", "read_only": True})
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(headers.get("Connection"), "close")
        status, _, raw = self._request("/.well-known/oauth-authorization-server")
        meta = json.loads(raw)
        self.assertEqual(meta["issuer"], "http://127.0.0.1:4711")
        status, _, raw = self._request("/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(json.loads(raw)["resource"], "http://127.0.0.1:4711/mcp")
        status, headers, raw = self._request_error("/mcp")
        self.assertEqual((status, headers.get("Allow")), (405, "POST, DELETE"))
        self.assertEqual(json.loads(raw), {"error": "no server-initiated stream"})
        status, _, raw = self._request_error("/nope")
        self.assertEqual((status, json.loads(raw)), (404, {"error": "not found"}))
        status, _, _ = self._request_error("/nope", method="DELETE")
        self.assertEqual(status, 404)
        status, _, _ = self._json_post("/nope", {"x": 1})
        self.assertEqual(status, 404)

    def test_authorize_page_rendering(self):
        status, _, raw = self._request_error("/authorize?client_id=WRONG")
        self.assertEqual((status, json.loads(raw)), (400, {"error": "invalid_client"}))
        query = ("client_id=cid-1&state=st%20x&scope=jarvis.read%20jarvis.admin%20bogus"
                 "&code_challenge=ch1&code_challenge_method=S256")
        status, headers, raw = self._request("/authorize?" + query)
        page = raw.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "text/html; charset=utf-8")
        self.assertIn('<input type="hidden" name="client_id" value="cid-1">', page)
        self.assertIn('<input type="hidden" name="state" value="st x">', page)
        self.assertIn('<input type="hidden" name="scope" value="jarvis.admin jarvis.read">', page)
        self.assertIn('<input type="hidden" name="code_challenge" value="ch1">', page)
        self.assertIn('<input type="hidden" name="code_challenge_method" value="S256">', page)
        self.assertIn('https://vertexaisearch.cloud.google.com/oauth-redirect', page)


class ConsentAndTokenTests(_ServerCase):
    def test_consent_flow_grant_and_refusal(self):
        refused = self._form_post("/authorize", {
            "passphrase": "zla", "client_id": "cid-1",
            "redirect_uri": "https://cb/cb", "state": "s1"})
        self.assertEqual(refused[0], 401)
        self.assertEqual(refused[1].get("Content-Type"), "text/html; charset=utf-8")
        self.assertIn(b"fraza zgody", refused[2])
        granted = self._form_post("/authorize", {
            "passphrase": PASSPHRASE, "client_id": "cid-1",
            "redirect_uri": "https://cb/cb", "state": "s1", "scope": "jarvis.read"})
        status, headers, _ = granted
        self.assertEqual(status, 302)
        location = headers.get("Location", "")
        self.assertTrue(location.startswith("https://cb/cb?code="))
        self.assertIn("state=s1", location)
        stored = list(face.CODES.values())
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["scope"], "jarvis.read")
        self.assertEqual(stored[0]["redirect_uri"], "https://cb/cb")
        with_query = self._form_post("/authorize", {
            "passphrase": PASSPHRASE, "client_id": "cid-1",
            "redirect_uri": "https://cb/cb?p=1"})
        self.assertIn("p=1&code=", with_query[1].get("Location", ""))

    def test_token_code_exchange_and_rejects(self):
        code, _ = self._grant_code()
        bad = self._token_exchange({"grant_type": "authorization_code",
                                    "client_id": "x", "client_secret": "y"})
        self.assertEqual((bad[0], json.loads(bad[2])), (401, {"error": "invalid_client"}))
        ok = self._token_exchange({"grant_type": "authorization_code", "code": code},
                                  basic="cid-1:csec-1")
        self.assertEqual(ok[0], 200)
        body = json.loads(ok[2])
        self.assertEqual(sorted(body),
                         ["access_token", "expires_in", "refresh_token", "scope", "token_type"])
        self.assertEqual(body["token_type"], "Bearer")
        self.assertEqual(body["expires_in"], 28800)
        self.assertTrue(body["access_token"].startswith("jmt_"))
        self.assertTrue(body["refresh_token"].startswith("jmr_"))
        replay = self._token_exchange({"grant_type": "authorization_code", "code": code},
                                      basic="cid-1:csec-1")
        self.assertEqual((replay[0], json.loads(replay[2])), (400, {"error": "invalid_grant"}))
        mismatch = self._token_exchange({"grant_type": "authorization_code",
                                         "code": self._grant_code(redirect_uri="https://one")[0],
                                         "client_id": "cid-1", "client_secret": "csec-1",
                                         "redirect_uri": "https://two"})
        self.assertEqual(json.loads(mismatch[2]),
                         {"error": "invalid_grant", "error_description": "redirect_uri mismatch"})

    def test_pkce_plain_and_s256(self):
        plain = self._grant_code(code_challenge="ver-ver", code_challenge_method="plain")
        ok = self._token_exchange({"grant_type": "authorization_code", "code": plain[0],
                                   "client_id": "cid-1", "client_secret": "csec-1",
                                   "code_verifier": "ver-ver"})
        self.assertEqual(ok[0], 200)
        with_redirect = self._grant_code(code_challenge="ver-ver", code_challenge_method="plain")
        refused = self._token_exchange({"grant_type": "authorization_code",
                                        "code": with_redirect[0],
                                        "client_id": "cid-1", "client_secret": "csec-1"})
        self.assertEqual(json.loads(refused[2]),
                         {"error": "invalid_request", "error_description": "code_verifier required"})
        verifier = "verifier-abc-123"
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        s256 = self._grant_code(code_challenge=challenge, code_challenge_method="S256")
        ok256 = self._token_exchange({"grant_type": "authorization_code",
                                      "code": s256[0], "client_id": "cid-1",
                                      "client_secret": "csec-1", "code_verifier": verifier})
        self.assertEqual(ok256[0], 200)
        bad = self._grant_code(code_challenge="X", code_challenge_method="S256")
        refused256 = self._token_exchange({"grant_type": "authorization_code",
                                           "code": bad[0], "client_id": "cid-1",
                                           "client_secret": "csec-1", "code_verifier": verifier})
        self.assertEqual((refused256[0], json.loads(refused256[2])),
                         (400, {"error": "invalid_grant", "error_description": "PKCE mismatch"}))

    def test_refresh_grant_rotation_and_unknown_grant(self):
        code, _ = self._grant_code()
        first = self._token_exchange({"grant_type": "authorization_code", "code": code,
                                      "client_id": "cid-1", "client_secret": "csec-1"})
        refresh_token = json.loads(first[2])["refresh_token"]
        refreshed = self._token_exchange({"grant_type": "refresh_token",
                                          "refresh_token": refresh_token,
                                          "client_id": "cid-1", "client_secret": "csec-1"})
        self.assertEqual(refreshed[0], 200)
        body = json.loads(refreshed[2])
        self.assertTrue(body["access_token"].startswith("jmt_"))
        stored = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        self.assertNotIn(refresh_token, stored["refresh"])
        self.assertIn(body["refresh_token"], stored["refresh"])
        replay = self._token_exchange({"grant_type": "refresh_token",
                                       "refresh_token": refresh_token,
                                       "client_id": "cid-1", "client_secret": "csec-1"})
        self.assertEqual((replay[0], json.loads(replay[2])),
                         (400, {"error": "invalid_grant"}))
        unknown = self._token_exchange({"grant_type": "password",
                                        "client_id": "cid-1", "client_secret": "csec-1"})
        self.assertEqual((unknown[0], json.loads(unknown[2])),
                         (400, {"error": "unsupported_grant_type"}))


class McpTransportTests(_ServerCase):
    def _access_token(self, scope="jarvis.read"):
        token, _ = face.issue_access(scope)
        return token

    def _post_mcp(self, payload, token=None, headers=None):
        token = token or self._access_token()
        return self._json_post("/mcp", payload, headers={"Authorization": "Bearer " + token,
                                                         **(headers or {})})

    def test_authorization_and_rate_limit(self):
        status, headers, raw = self._json_post("/mcp", {"jsonrpc": "2.0", "id": 1,
                                                        "method": "ping"})
        self.assertEqual((status, json.loads(raw)), (401, {"error": "invalid_token"}))
        self.assertEqual(
            headers.get("WWW-Authenticate"),
            'Bearer realm="jarvis", resource_metadata="http://127.0.0.1:4711'
            '/.well-known/oauth-protected-resource"')
        face.RATE["127.0.0.1"] = [time.time() - 1.0] * 90
        status, _, raw = self._post_mcp({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        self.assertEqual((status, json.loads(raw)), (429, {"error": "too many requests"}))

    def test_initialize_sessions_and_parse_errors(self):
        token = self._access_token()
        status, headers, raw = self._post_mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                               "params": {"protocolVersion": "2025-06-18"}}, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["result"]["protocolVersion"], "2025-06-18")
        sid = headers.get("Mcp-Session-Id")
        self.assertEqual(len(sid or ""), 24)
        status, _, raw = self._post_mcp({"jsonrpc": "2.0", "id": 2, "method": "ping"},
                                         token=token, headers={"Mcp-Session-Id": sid})
        self.assertEqual((status, json.loads(raw)["result"]), (200, {}))
        status, _, raw = self._post_mcp({"jsonrpc": "2.0", "id": 3, "method": "ping"},
                                        token=token, headers={"Mcp-Session-Id": "bogus-sid"})
        self.assertEqual((status, json.loads(raw)), (404, {"error": "unknown session"}))
        status, _, raw = self._request_error("/mcp", method="POST", data=b"{oops",
                                             headers={"Content-Type": "application/json",
                                                      "Authorization": "Bearer " + token})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)["error"]["code"], -32700)
        status, _, raw = self._post_mcp({"jsonrpc": "2.0", "method": "notifications/x"}, token=token)
        self.assertEqual((status, raw), (202, b""))
        status, _, raw = self._post_mcp([{"jsonrpc": "2.0", "id": 9, "method": "ping"}], token=token)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["error"]["code"], -32600)

    def test_scope_guard_tool_calls_and_sse(self):
        token = self._access_token("jarvis.read")
        status, _, raw = self._post_mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                                        token=token)
        self.assertEqual(len(json.loads(raw)["result"]["tools"]), 12)
        status, _, raw = self._post_mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                         "params": {"name": "remember",
                                                    "arguments": {"text": "x"}}}, token=token)
        result = json.loads(raw)["result"]
        self.assertTrue(result["isError"])
        self.assertIn("This token carries only jarvis.read", result["content"][0]["text"])
        self.assertNotIn("structuredContent", result)

        class FakeResponse:
            def read(self):
                return b'{"answer": "ok"}'

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def fake_urlopen(request, timeout=None):
            return FakeResponse()

        with mock.patch.object(urllib.request, "urlopen", fake_urlopen):
            status, _, raw = self._post_mcp({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                             "params": {"name": "ask",
                                                        "arguments": {"question": "hej"}}}, token=token)
        happy = json.loads(raw)["result"]
        self.assertFalse(happy["isError"])
        self.assertEqual(happy["structuredContent"], {"answer": "ok"})
        status, headers, raw = self._post_mcp({"jsonrpc": "2.0", "id": 4, "method": "ping"},
                                              token=token,
                                              headers={"Accept": "text/event-stream"})
        self.assertEqual((status, headers.get("Content-Type")), (200, "text/event-stream"))
        self.assertEqual(raw, b'event: message\ndata: {"jsonrpc": "2.0", "id": 4, "result": {}}\n\n')

    def test_delete_closes_session(self):
        token = self._access_token()
        status, headers, _ = self._post_mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, token=token)
        self.assertEqual(status, 200)
        sid = headers.get("Mcp-Session-Id")
        self.assertIn(sid, face.SESSIONS)
        status, _, raw = self._request_error("/mcp", method="DELETE",
                                             headers={"Mcp-Session-Id": sid})
        self.assertEqual((status, raw), (204, b""))
        self.assertNotIn(sid, face.SESSIONS)


class SetupAndPassphraseTests(_FaceCase):
    def test_show_setup_prints_credentials(self):
        buffer = io.StringIO()
        with mock.patch.object(sys, "stdout", buffer):
            rc = face.show_setup()
        self.assertEqual(rc, 0)
        lines = buffer.getvalue().strip().splitlines()
        self.assertEqual(lines[0], "public_url      : http://127.0.0.1:4711")
        self.assertEqual(lines[1], "MCP server URL  : http://127.0.0.1:4711/mcp")
        self.assertIn("client_id", lines[4])
        self.assertIn("client_secret", lines[5])
        self.assertIn("jarvis.read jarvis.admin", lines[6])
        self.assertEqual(lines[7], "redirect_uri    : "
                         "https://vertexaisearch.cloud.google.com/oauth-redirect")
        self.assertEqual(lines[8], f"state file      : {STATE_PATH}")

    def test_set_passphrase_cli(self):
        error = io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO("krotkie\n")), \
                mock.patch.object(sys, "stderr", error):
            rc = face.set_passphrase()
        self.assertEqual(rc, 1)
        self.assertEqual(error.getvalue().strip(), "Fraza musi mieć co najmniej 8 znaków.")
        seed_state({"passphrase_generated": True})
        with mock.patch.object(sys, "stdin", io.StringIO("nowa-fraza-dobra\n")), \
                mock.patch.object(sys, "stdout", io.StringIO()):
            rc = face.set_passphrase()
        self.assertEqual(rc, 0)
        state = face.load_state()
        self.assertTrue(face.passphrase_ok(state, "nowa-fraza-dobra"))
        self.assertFalse(face.passphrase_ok(state, PASSPHRASE))
        self.assertNotIn("passphrase_generated", state)


if __name__ == "__main__":
    import unittest
    unittest.main()
