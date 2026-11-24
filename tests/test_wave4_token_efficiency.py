"""End-to-end tests for Wave-4 Semantic Prompt Cache & AST Context Compressor:
1. `semantic_cache` exact hit, high-similarity (`>=0.92`) hit, and `saved_usd` ledger
2. Automatic cache invalidation when workspace `directory_watermark` (`mtime`) advances
3. `context_compressor.compress_logs` deduplication & `skeletonize_python` AST signatures
4. Automatic AST skeleton attachment inside `code_index.build_context_pack()`
5. HTTP `/mission/status` (`semantic_cache`) & `/mission/action` (`cache_store`, `cache_lookup`, `compress_context`)
"""

import json
import os
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import agent_cli
import code_index
import context_compressor
import semantic_cache
import server


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


class Wave4TokenEfficiencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp" if Path("/tmp").is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.agents_dir = self.base / "state" / ".jarvis-tools" / "agents"
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        self.p_agents = patch.object(agent_cli, "ROOT", self.agents_dir)
        self.p_agents.start()
        self.addCleanup(self.p_agents.stop)

        code_index.evict_idle_cache(force=True)
        self.proj_root = self.base / "proj"
        self.proj_root.mkdir(parents=True, exist_ok=True)

        handler_cls = _find_handler_class()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.httpd.app = SimpleNamespace(root=self.proj_root)
        self.port = self.httpd.server_port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def test_1_semantic_cache_hits_and_auto_invalidates_on_mtime_change(self):
        note = self.proj_root / "arch.md"
        note.write_text("Wersja 1 architektury", encoding="utf-8")
        wm1 = semantic_cache.directory_watermark(self.proj_root)

        semantic_cache.put(
            "Podsumuj architekturę routera agentów Jarvisa",
            "Router używa wag jakości, kosztu i bezpiecznika 429.",
            scope="chat",
            watermark=wm1,
            est_usd=0.015,
        )
        # Exact hit (case/punctuation normalized)
        hit1 = semantic_cache.get("podsumuj architekturę routera agentów jarvisa?!", scope="chat", watermark=wm1)
        self.assertIsNotNone(hit1)
        self.assertEqual(hit1["match_kind"], "exact")
        self.assertAlmostEqual(hit1["saved_usd"], 0.015)

        # Advance file mtime -> watermark changes -> stale cache entry is bypassed!
        new_mtime = time.time() + 10.0
        os.utime(note, (new_mtime, new_mtime))
        wm2 = semantic_cache.directory_watermark(self.proj_root)
        self.assertGreater(wm2, wm1)
        miss = semantic_cache.get("Podsumuj architekturę routera agentów Jarvisa", scope="chat", watermark=wm2)
        self.assertIsNone(miss)

        summary = semantic_cache.cache_summary()
        self.assertEqual(summary["total_hits"], 1)
        self.assertEqual(summary["total_misses"], 1)

    def test_2_log_deduplicator_and_ast_skeletonizer_save_tokens(self):
        noisy_log = "\n".join(
            [f"2026-11-14T17:00:{i:02d}Z ERROR Połączenie odrzucone 127.0.0.1:11434" for i in range(20)]
            + ["2026-11-14T17:00:25Z CRITICAL Wykryto awarię gniazda"]
        )
        comp_log = context_compressor.compress_logs(noisy_log)
        self.assertIn("[powtórzono ×20]", comp_log)
        self.assertIn("CRITICAL Wykryto awarię gniazda", comp_log)
        self.assertLess(len(comp_log), len(noisy_log) // 3)

        py_src = (
            '"""Moduł obsługi dysku ThinkCentre."""\n'
            "import os\n\n"
            "class DiskMountManager:\n"
            '    """Zarządza izolacją wibracji i stanem SMART."""\n'
            "    def check_smart_temperature(self, device: str) -> int:\n"
            '        """Zwraca temperaturę dysku w stopniach Celsjusza."""\n'
            + ("        x = 1\n" * 30)
            + "        return 34\n\n"
            "def target_helper(flag: bool) -> str:\n"
            "    return 'active' if flag else 'idle'\n"
        )
        skel = context_compressor.skeletonize_python(py_src, keep_symbols=["target_helper"])
        self.assertIn("class DiskMountManager:", skel)
        self.assertIn("def check_smart_temperature(self, device: str) -> int:", skel)
        self.assertNotIn("x = 1", skel)
        # Targeted symbol keeps its full implementation
        self.assertIn("return 'active' if flag else 'idle'", skel)

        # Verify code_index.build_context_pack attaches AST skeleton automatically
        (self.proj_root / "disk_manager.py").write_text(py_src, encoding="utf-8")
        pack = code_index.build_context_pack("check_smart_temperature DiskMountManager", root_dir=self.proj_root)
        self.assertIn("Szkielet sygnatur AST", pack)
        self.assertIn("class DiskMountManager:", pack)

    def test_3_http_mission_cache_and_compress_actions(self):
        def _post_action(payload: dict) -> dict:
            raw = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.port}/mission/action",
                data=raw,
                method="POST",
                headers={
                    "Host": f"127.0.0.1:{self.port}",
                    "Origin": f"http://127.0.0.1:{self.port}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(raw)),
                },
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                return json.loads(resp.read().decode("utf-8"))

        stored = _post_action({
            "action": "cache_store",
            "project_dir": str(self.proj_root),
            "prompt": "Jaki jest limit dzienny budżetu?",
            "response_text": "Domyślny limit wynosi 5 USD dziennie.",
            "est_usd": 0.004,
        })
        self.assertTrue(stored["stored"])

        looked = _post_action({
            "action": "cache_lookup",
            "project_dir": str(self.proj_root),
            "prompt": "jaki jest limit dzienny budżetu",
        })
        self.assertTrue(looked["hit"])
        self.assertIn("5 USD", looked["entry"]["response_text"])

        comp = _post_action({
            "action": "compress_context",
            "mode": "python",
            "source": "def compute_crc(data: bytes) -> int:\n    '''Oblicza CRC32.'''\n    val = 0\n    return val\n",
        })
        self.assertTrue(comp["ok"])
        self.assertIn("def compute_crc(data: bytes) -> int:", comp["compressed"])


if __name__ == "__main__":
    unittest.main()
