"""Integration tests for new Jarvis capabilities:

- Piper TTS with JARVIS Paul Bettany voice
- Storage Guard / disk headroom inspection
- Desktop Tracker X11 activity history
- Vault Watcher auto-rebuild
"""
import http.client
import json
import tempfile
import threading
import os
import unittest
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
from pathlib import Path
from unittest.mock import MagicMock, patch

import server


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class TestNewCapabilities(unittest.TestCase):

    def setUp(self):
        env = patch.dict("os.environ", {"JARVIS_EMBEDDINGS": "off"})
        env.start()
        self.addCleanup(env.stop)
        for bucket in server.PAID_BUCKETS.values():
            bucket.rate = 0.0
            bucket.capacity = 0.0
            bucket.tokens = 0.0
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.viewer = self.root / "viewer"
        self.viewer.mkdir()
        (self.viewer / "index.html").write_text("<!doctype html><title>Vault</title>")
        self.notes = self.root / "notes"
        self.notes.mkdir()
        (self.notes / "note-0.md").write_text("# Mars\nMars is red.")
        (self.viewer / "graph-data.js").write_text('const GRAPH = {"nodes": [], "links": []};\n')
        (self.root / "config.json").write_text(json.dumps({"aOPENROUTER_API_KEY": "test", "model": "test"}))
        self.client = MagicMock()
        self.factory = MagicMock(return_value=self.client)
        self.state = self.root / "state"
        self.state.mkdir()
        self.httpd = server.create_server(root=self.root, notes_root=self.notes,
                                          port=0, client_factory=self.factory,
                                          state_root=self.state,
                                          enable_agent=False, enable_scheduler=False,
                                          enable_memory_capture=False)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.port = self.httpd.server_address[1]

    def stop_server(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)

    def request(self, path="/chat", body=None, headers=None, method="POST", raw=None):
        payload = raw if raw is not None else json.dumps(body or {})
        request_headers = {"Content-Type": "application/json", **(headers or {})}
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=4)
        self.addCleanup(connection.close)
        connection.request(method, path, body=payload if method == "POST" else None,
                           headers=request_headers)
        response = connection.getresponse()
        data = response.read()
        return response.status, dict(response.getheaders()), data

    def test_piper_voice_tts_endpoint(self):
        status, headers, body = self.request(
            path="/tts",
            body={"text": "At your service, sir.", "voice": "en_GB-jarvis-medium"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "audio/wav")
        self.assertTrue(body.startswith(b"RIFF"))

    def test_storage_status_endpoint(self):
        status, _, raw = self.request(path="/storage/status", method="GET")
        self.assertEqual(status, 200)
        data = json.loads(raw)
        self.assertTrue(data.get("ok"))
        self.assertIn("free_gb", data)
        self.assertIn("percent_used", data)
        self.assertIn("warning", data)

    def test_desktop_history_endpoint(self):
        status, _, raw = self.request(path="/desktop/history?limit=5", method="GET")
        self.assertEqual(status, 200)
        data = json.loads(raw)
        self.assertTrue(data.get("ok"))
        self.assertIn("history", data)
        self.assertIn("count", data)

    def test_vault_watcher_status_and_rebuild(self):
        status, _, raw = self.request(path="/vault/watcher", method="GET")
        self.assertEqual(status, 200)
        data = json.loads(raw)
        self.assertIn("vault", data)
        self.assertIn("rebuild_count", data)

        status, _, raw = self.request(path="/vault/rebuild", raw="{}")
        self.assertEqual(status, 200)
        rebuild_data = json.loads(raw)
        self.assertTrue(rebuild_data.get("ok"))
        self.assertGreater(rebuild_data.get("notes", 0), 0)


if __name__ == "__main__":
    unittest.main()
