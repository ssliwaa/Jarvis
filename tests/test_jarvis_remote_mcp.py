"""Remote MCP bridge: sandboxed file tools, subprocess/system tooling, agents bridge
dispatch, Streamable HTTP + OAuth 2.0 handler and banner/CLI contracts."""
import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock

import jarvis_remote_mcp as jrm


class _TmpRootCase(TestCase):
    """Isolated PROJECT_ROOT inside tmp for every test."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self._patcher = mock.patch.object(jrm, "PROJECT_ROOT", self.root)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)

    def _mkdir_tree(self):
        (self.root / "pkg").mkdir()
        (self.root / "pkg" / "mod.py").write_text("X = 0\nY = 1\nZ = 2\nW = 3\nQ = 5\n", encoding="utf-8")


class AuthConfigTests(TestCase):
    """load_or_create_auth on a tmp CONFIG_DIR (never the real ~/.jarvis-tools)."""

    def setUp(self):
        self.cfg_dir = Path(tempfile.mkdtemp())
        self._cfg = mock.patch.object(jrm, "CONFIG_DIR", self.cfg_dir)
        self._path = mock.patch.object(jrm, "AUTH_CONFIG_PATH", self.cfg_dir / "remote-mcp-auth.json")
        self._cfg.start()
        self._path.start()
        self.addCleanup(self._cfg.stop)
        self.addCleanup(self._path.stop)

    def test_creates_config_with_modes_and_shape(self):
        auth = jrm.load_or_create_auth()
        self.assertEqual(sorted(auth), ["client_id", "client_secret", "secret_slug", "signing_key"])
        self.assertTrue(auth["client_id"].startswith("jarvis-mcp-"))
        self.assertEqual(len(auth["client_secret"]), 43)
        self.assertEqual(len(auth["signing_key"]), 64)
        stored = json.loads((self.cfg_dir / "remote-mcp-auth.json").read_text(encoding="utf-8"))
        self.assertEqual(stored, auth)
        self.assertEqual(oct((self.cfg_dir / "remote-mcp-auth.json").stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(self.cfg_dir.stat().st_mode & 0o777), "0o700")

    def test_reload_is_stable(self):
        first = jrm.load_or_create_auth()
        second = jrm.load_or_create_auth()
        self.assertEqual(first, second)
        stored = json.loads((self.cfg_dir / "remote-mcp-auth.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["secret_slug"], first["secret_slug"])

    def test_corrupt_or_partial_config_regenerates(self):
        first = jrm.load_or_create_auth()
        cfg_file = self.cfg_dir / "remote-mcp-auth.json"
        cfg_file.write_text("{corrupt", encoding="utf-8")
        regenerated = jrm.load_or_create_auth()
        self.assertNotEqual(regenerated, first)
        cfg_file.write_text(json.dumps({"secret_slug": "partial"}), encoding="utf-8")
        partial = jrm.load_or_create_auth()
        self.assertEqual(sorted(partial), ["client_id", "client_secret", "secret_slug", "signing_key"])


class TokenTests(TestCase):
    """HMAC-signed base64url JSON tokens (sign/verify)."""

    def _token(self, exp):
        return jrm._sign_token({"sub": "jarvis-owner", "exp": exp}, "KEY-123")

    def test_sign_verify_roundtrip_and_format(self):
        token = jrm._sign_token({"sub": "jarvis-owner", "exp": time.time() + 100}, "KEY-123")
        raw, _, sig = token.partition(".")
        self.assertEqual(len(sig), 64)
        self.assertFalse(token.endswith("="))
        self.assertTrue(jrm._verify_token(token, "KEY-123"))
        self.assertEqual(jrm._sign_token({"a": 1}, "k"), jrm._sign_token({"a": 1}, "k"))

    def test_verify_rejects_garbage_expired_wrongkey_tampering(self):
        expired = self._token(time.time() - 5)
        self.assertFalse(jrm._verify_token(expired, "KEY-123"))
        self.assertFalse(jrm._verify_token(self._token(time.time() + 5), "OTHER-KEY"))
        self.assertFalse(jrm._verify_token("", "k"))
        self.assertFalse(jrm._verify_token("nodot", "k"))
        self.assertFalse(jrm._verify_token("abc.not-hex", "k"))
        token = self._token(time.time() + 50)
        self.assertFalse(jrm._verify_token(token + "x", "KEY-123"))
        self.assertFalse(jrm._verify_token(token.rsplit(".", 1)[0] + "." + "0" * 64, "KEY-123"))


class PathSafetyTests(_TmpRootCase):
    """_safe_project_path sandbox rules and exact Polish error messages."""

    def test_valid_paths_and_absolute_strip(self):
        self._mkdir_tree()
        got = jrm._safe_project_path("pkg/mod.py")
        self.assertEqual(str(got.relative_to(self.root)), "pkg/mod.py")
        stripped = jrm._safe_project_path("/pkg/mod.py")
        self.assertEqual(stripped.name, "mod.py")
        new_one = jrm._safe_project_path("fresh/thing.py", allow_missing=True)
        self.assertEqual(new_one.name, "thing.py")
        self.assertFalse(new_one.exists())

    def test_rejects_dotdot_empty_and_missing(self):
        self._mkdir_tree()
        with self.assertRaises(ValueError) as ctx:
            jrm._safe_project_path("a/../..")
        self.assertEqual(str(ctx.exception),
                         "Ścieżka musi być względna wewnątrz katalogu projektu Jarvis (bez '..').")
        with self.assertRaises(ValueError) as ctx:
            jrm._safe_project_path("   ")
        self.assertEqual(str(ctx.exception),
                         "Ścieżka musi być względna wewnątrz katalogu projektu Jarvis (bez '..').")
        with self.assertRaises(ValueError) as ctx:
            jrm._safe_project_path("pkg/missing.py")
        self.assertEqual(str(ctx.exception), "Plik nie istnieje: pkg/missing.py")

    def test_rejects_forbidden_dirs_files_suffixes(self):
        self._mkdir_tree()
        for rel in (".git/config", ".ssh/id_rsa"):
            with self.assertRaises(ValueError) as ctx:
                jrm._safe_project_path(rel, allow_missing=True)
            self.assertEqual(str(ctx.exception), f"Odmowa dostępu do chronionego katalogu: {rel.split('/')[0]}")
        for rel in (".env", ".env.local", "secrets.json", "credentials.json", "consent.json"):
            with self.assertRaises(ValueError) as ctx:
                jrm._safe_project_path(rel, allow_missing=True)
            self.assertEqual(str(ctx.exception), "Odmowa dostępu do pliku z sekretami.")
        for rel in ("x.pem", "id_ed25519", "data.sqlite"):
            with self.assertRaises(ValueError) as ctx:
                jrm._safe_project_path(rel, allow_missing=True)
            self.assertIn(str(ctx.exception), ("Odmowa dostępu do kluczy/baz binarnych.",
                                               "Odmowa dostępu do pliku z sekretami."))

    def test_symlink_escape_rejected(self):
        self._mkdir_tree()
        outside = Path(tempfile.mkdtemp())
        (outside / "target").write_text("outside", encoding="utf-8")
        os.symlink(outside / "target", self.root / "escape.py")
        with self.assertRaises(ValueError) as ctx:
            jrm._safe_project_path("escape.py")
        self.assertEqual(str(ctx.exception),
                         "Odmowa dostępu: ścieżka wychodzi poza katalog projektu Jarvis.")


class FileToolsTests(_TmpRootCase):
    """jarvis_list_files / read / search / write / patch contracts."""

    def test_list_files_root_subdir_and_query(self):
        self._mkdir_tree()
        (self.root / ".env").write_text("SECRET=1", encoding="utf-8")
        res = jrm.execute_tool("jarvis_list_files", {})
        self.assertTrue(res["ok"])
        self.assertEqual(res["root"], str(self.root))
        paths = [r["path"] for r in res["files"]]
        self.assertEqual(sorted(paths), ["pkg/mod.py"])
        self.assertTrue(all("bytes" in r for r in res["files"]))
        sub = jrm.execute_tool("jarvis_list_files", {"subdir": "pkg"})
        self.assertEqual([r["path"] for r in sub["files"]], ["pkg/mod.py"])
        hit = jrm.execute_tool("jarvis_list_files", {"query": "MOD.PY"})
        self.assertEqual([r["path"] for r in hit["files"]], ["pkg/mod.py"])
        miss = jrm.execute_tool("jarvis_list_files", {"query": "no-such-thing"})
        self.assertEqual(miss["files"], [])

    def test_list_files_cap_300(self):
        (self.root / "many").mkdir()
        for i in range(305):
            (self.root / "many" / f"f{i:03d}.txt").write_text("x", encoding="utf-8")
        res = jrm.execute_tool("jarvis_list_files", {"subdir": "many"})
        self.assertEqual(res["count"], 300)

    def test_read_file_numbering_and_ranges(self):
        self._mkdir_tree()
        res = jrm.execute_tool("jarvis_read_file", {"path": "pkg/mod.py"})
        self.assertEqual(res["shown_lines"], "1..5")
        self.assertEqual(res["total_lines"], 5)
        self.assertNotIn("truncated", res)
        self.assertEqual(res["content"], "1: X = 0\n2: Y = 1\n3: Z = 2\n4: W = 3\n5: Q = 5")
        rng = jrm.execute_tool("jarvis_read_file", {"path": "pkg/mod.py", "start_line": 2, "end_line": 4})
        self.assertEqual(rng["shown_lines"], "2..4")
        self.assertEqual(rng["content"], "2: Y = 1\n3: Z = 2\n4: W = 3")
        over = jrm.execute_tool("jarvis_read_file", {"path": "pkg/mod.py", "start_line": 99})
        self.assertEqual(over["shown_lines"], "99..5")
        self.assertEqual(over["content"], "")

    def test_read_oversized_window_hardening(self):
        (self.root / "huge.py").write_text(('l = "%s"\n' % ("x" * 30)) * 7000, encoding="utf-8")
        no_range = jrm.execute_tool("jarvis_read_file", {"path": "huge.py"})
        self.assertTrue(no_range.get("truncated"))
        self.assertEqual(no_range["shown_lines"], "1..251")
        self.assertEqual(len(no_range["content"].splitlines()), 251)
        # hardening: samo start_line nie może już zwrócić całego 252KB pliku
        start_only = jrm.execute_tool("jarvis_read_file", {"path": "huge.py", "start_line": 1})
        self.assertTrue(start_only.get("truncated"))
        self.assertEqual(start_only["shown_lines"], "1..251")
        self.assertEqual(len(start_only["content"].splitlines()), 251)
        window = jrm.execute_tool("jarvis_read_file", {"path": "huge.py", "start_line": 100})
        self.assertEqual(window["shown_lines"], "100..350")
        self.assertTrue(window.get("truncated"))
        # jawny end_line to świadoma prośba -> bez capu
        explicit = jrm.execute_tool("jarvis_read_file", {"path": "huge.py", "start_line": 1, "end_line": 300})
        self.assertEqual(explicit["shown_lines"], "1..300")
        self.assertNotIn("truncated", explicit)
        end_only = jrm.execute_tool("jarvis_read_file", {"path": "huge.py", "end_line": 300})
        self.assertEqual(end_only["shown_lines"], "1..300")
        self.assertNotIn("truncated", end_only)

    def test_search_code_hits_limits_and_guards(self):
        (self.root / "notes.txt").write_text("ala ma kota\n", encoding="utf-8")
        (self.root / ".env").write_text("SECRET=42\n", encoding="utf-8")
        res = jrm.execute_tool("jarvis_search_code", {"pattern": "KotA"})
        self.assertEqual(res["hits"], [{"path": "notes.txt", "line": 1, "text": "ala ma kota"}])
        self.assertFalse(res["truncated"])
        with self.assertRaises(ValueError) as ctx:
            jrm.execute_tool("jarvis_search_code", {})
        self.assertEqual(str(ctx.exception), "Podaj 'pattern'.")
        limited = jrm.execute_tool("jarvis_search_code", {"pattern": "ala", "max_hits": 2})
        self.assertEqual(len(limited["hits"]), 1)
        secretless = jrm.execute_tool("jarvis_search_code", {"pattern": "SECRET"})
        self.assertEqual(secretless["hits"], [])
        (self.root / "spin.txt").write_text("MARK\n" * 130, encoding="utf-8")
        clamped = jrm.execute_tool("jarvis_search_code", {"pattern": "MARK", "max_hits": 999})
        self.assertEqual(len(clamped["hits"]), 120)
        self.assertTrue(clamped["truncated"])
        self.assertEqual(clamped["hits"][0], {"path": "spin.txt", "line": 1, "text": "MARK"})
        single = jrm.execute_tool("jarvis_search_code", {"pattern": "MARK", "subdir": "spin.txt", "max_hits": 2})
        self.assertEqual(len(single["hits"]), 2)
        self.assertTrue(single["truncated"])
        big = self.root / "blob.bin.txt"
        big.write_text("MARK" + "x" * 600_000, encoding="utf-8")
        skipped = jrm.execute_tool("jarvis_search_code", {"pattern": "MARK", "subdir": "blob.bin.txt"})
        self.assertEqual(skipped["hits"], [])

    def test_write_file_backup_syntax_and_size_limits(self):
        self._mkdir_tree()
        created = jrm.execute_tool("jarvis_write_file", {"path": "docs/new.md", "content": "# hi"})
        self.assertTrue(created["ok"])
        self.assertEqual(created["path"], "docs/new.md")
        self.assertEqual(created["bytes"], 4)
        self.assertIsNone(created["backup"])
        self.assertEqual((self.root / "docs" / "new.md").read_text(encoding="utf-8"), "# hi")
        overwritten = jrm.execute_tool("jarvis_write_file", {"path": "pkg/mod.py", "content": "X = 9\n"})
        self.assertIsNotNone(overwritten["backup"])
        self.assertTrue(str(Path(overwritten["backup"])).startswith(".jarvis-mcp-backups/"))
        self.assertTrue(str(Path(overwritten["backup"])).endswith("pkg__mod.py.bak"))
        self.assertTrue((self.root / overwritten["backup"]).is_file())
        with self.assertRaises(ValueError) as ctx:
            jrm.execute_tool("jarvis_write_file", {"path": "bad.py", "content": "def f(:\n"})
        self.assertEqual(str(ctx.exception), "Odrzucono zapis — błąd składni Python w linii 1: invalid syntax")
        self.assertFalse((self.root / "bad.py").exists())
        with self.assertRaises(ValueError) as ctx:
            jrm.execute_tool("jarvis_write_file", {"path": "big.txt", "content": "x" * 400_001})
        self.assertEqual(str(ctx.exception), "Plik przekracza limit 400000 bajtów.")
        self.assertFalse((self.root / "big.txt").exists())
        with self.assertRaises(ValueError) as ctx:
            jrm.execute_tool("jarvis_write_file", {"path": ".env", "content": "x"})
        self.assertEqual(str(ctx.exception), "Odmowa dostępu do pliku z sekretami.")
        self.assertFalse((self.root / "bad.py").exists())

    def test_patch_file_contracts(self):
        self._mkdir_tree()
        (self.root / "dup.txt").write_text("ala ma kota\nala ma kota\npies\n", encoding="utf-8")
        res = jrm.execute_tool("jarvis_patch_file", {"path": "dup.txt", "old_text": "pies", "new_text": "kot"})
        self.assertTrue(res["ok"])
        self.assertIsNotNone(res["backup"])
        self.assertEqual((self.root / "dup.txt").read_text(encoding="utf-8"), "ala ma kota\nala ma kota\nkot\n")
        with self.assertRaises(ValueError) as ctx:
            jrm.execute_tool("jarvis_patch_file", {"path": "dup.txt", "old_text": "ala ma kota", "new_text": "x"})
        self.assertEqual(str(ctx.exception), "Fragment 'old_text' występuje wielokrotnie — podaj więcej kontekstu.")
        with self.assertRaises(ValueError) as ctx:
            jrm.execute_tool("jarvis_patch_file", {"path": "dup.txt", "old_text": "no-such", "new_text": "x"})
        self.assertEqual(str(ctx.exception), "Nie znaleziono dokładnego fragmentu 'old_text' w pliku.")
        with self.assertRaises(ValueError) as ctx:
            jrm.execute_tool("jarvis_patch_file", {"path": "pkg/mod.py", "old_text": "X = 0", "new_text": "X = (:"})
        self.assertEqual(str(ctx.exception), "Odrzucono zapis — błąd składni Python w linii 1: invalid syntax")

    def test_unknown_tool_raises(self):
        with self.assertRaises(ValueError) as ctx:
            jrm.execute_tool("nope_tool", {})
        self.assertEqual(str(ctx.exception), "Nieznane narzędzie MCP: nope_tool")


class SubprocessToolsTests(_TmpRootCase):
    """jarvis_run_checks / jarvis_service_control with a fully faked subprocess."""

    def setUp(self):
        super().setUp()
        self.calls = []

        def fake_run(cmd, **kwargs):
            self.calls.append((list(cmd), kwargs))
            if "scripts/lint.py" in cmd:
                return SimpleNamespace(returncode=1, stdout="LINT-OUT", stderr="LINT-ERR")
            if "-m" in cmd and "unittest" in cmd:
                return SimpleNamespace(returncode=0, stdout="", stderr="TESTS-ERR")
            if "systemctl" in cmd:
                return SimpleNamespace(returncode=0, stdout="active\n", stderr="boom")
            if "journalctl" in cmd:
                return SimpleNamespace(returncode=0, stdout="LOG1\nLOG2\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        patcher = mock.patch.object(subprocess, "run", fake_run)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_run_checks_default_lint(self):
        res = jrm.execute_tool("jarvis_run_checks", {})
        self.assertTrue(res["ok"])
        self.assertEqual(sorted(res), ["lint", "ok"])
        self.assertEqual(res["lint"]["exit_code"], 1)
        self.assertEqual(res["lint"]["output"], "LINT-OUTLINT-ERR")
        cmd, kwargs = self.calls[0]
        self.assertEqual(cmd[1:], ["scripts/lint.py"])
        self.assertEqual(kwargs["cwd"], str(self.root))
        self.assertEqual(kwargs["timeout"], 45)
        self.assertTrue(kwargs["capture_output"])
        self.assertFalse(kwargs["check"])

    def test_run_checks_tests_mapping_and_existence_gate(self):
        (self.root / "tests").mkdir()
        for i in range(13):
            (self.root / "tests" / f"t{i:02d}.py").write_text("pass\n", encoding="utf-8")
        names = [f"tests/t{i:02d}.py" for i in range(13)]
        res = jrm.execute_tool("jarvis_run_checks", {"lint": False, "tests": names})
        self.assertEqual(sorted(res), ["ok", "unittest"])
        self.assertEqual(res["unittest"]["output"], "TESTS-ERR")
        cmd, kwargs = self.calls[0]
        self.assertEqual(cmd[1:3], ["-m", "unittest"])
        self.assertEqual(cmd[3:3 + 12], names[:12])
        self.assertEqual(kwargs["timeout"], 90)
        with self.assertRaises(ValueError) as ctx:
            jrm.execute_tool("jarvis_run_checks", {"lint": False, "tests": ["tests/missing.py"]})
        self.assertEqual(str(ctx.exception), "Plik nie istnieje: tests/missing.py")
        only_lint = jrm.execute_tool("jarvis_run_checks", {"lint": True, "tests": []})
        self.assertEqual(sorted(only_lint), ["lint", "ok"])

    def test_service_control_matrix(self):
        res = jrm.execute_tool("jarvis_service_control", {"action": "restart"})
        self.assertEqual(res, {"ok": True, "exit_code": 0, "stderr": "boom"})
        self.assertEqual(self.calls[0][0], ["systemctl", "--user", "restart", "jarvis.service"])
        self.assertEqual(self.calls[0][1]["timeout"], 25)
        res = jrm.execute_tool("jarvis_service_control", {"action": "status"})
        self.assertEqual(res, {"ok": True, "state": "active"})
        self.assertEqual(self.calls[1][0], ["systemctl", "--user", "is-active", "jarvis.service"])
        res = jrm.execute_tool("jarvis_service_control", {"action": "logs", "lines": 5})
        self.assertEqual(res, {"ok": True, "logs": "LOG1\nLOG2\n"})
        self.assertEqual(self.calls[2][0][5], "10")
        jrm.execute_tool("jarvis_service_control", {"action": "logs", "lines": 999})
        self.assertEqual(self.calls[3][0][5], "200")
        jrm.execute_tool("jarvis_service_control", {"action": "logs"})
        self.assertEqual(self.calls[4][0][5], "50")
        with self.assertRaises(ValueError) as ctx:
            jrm.execute_tool("jarvis_service_control", {"action": "explode"})
        self.assertEqual(str(ctx.exception), "Nieznana akcja jarvis_service_control.")


def _make_agent_fakes():
    cli = SimpleNamespace(
        summary=lambda: {"agents": 2},
        live_progress=lambda aid: {"agent": aid, "run": "x"},
        agent_ids=lambda: ["opus", "son"],
        outbox=lambda aid: {"aid": aid, "files": ["a"]},
        tail=lambda aid: f"TAIL-{aid}",
        start_async=lambda aid, task, **kw: {"started": aid, "task": task, **kw},
        stop=lambda aid: {"stopped": aid},
    )
    team = SimpleNamespace(
        list_projects=lambda n=5: [f"p{i}" for i in range(n)],
        project_status=lambda pid: {"pid": pid.lower(), "st": "running"},
        start_parallel_wave=lambda pid, **kw: {"wave": pid, **kw},
        start_team_project=lambda **kw: {"project": kw.get("project_id") or "new", **kw},
        post_message=lambda pid, **kw: {"posted": kw},
        read_messages=lambda pid, limit=5: ["m"] * limit,
        nudge_agent=lambda pid, aid, msg, **kw: {"nudged": aid, **kw},
        stop_project=lambda pid: {"stopped": pid},
    )
    router = SimpleNamespace(pick_best_agent=lambda task="": "hermes", router_summary=lambda: {"routes": 1})
    review = SimpleNamespace(diff_outbox=lambda tid, target: {"diff": tid},
                             apply_outbox=lambda tid, target: {"applied": tid},
                             rollback_last_checkpoint=lambda target: {"rolled": target})
    watchdog = SimpleNamespace(scan_logs=lambda auto_repair=False, project_root="": {"auto": auto_repair, "root": project_root})
    code_index = SimpleNamespace(search_context=lambda q, root_dir="": {"q": q, "root": root_dir})
    voice = SimpleNamespace(pending_owner_questions=lambda pid: ["q1"],
                            answer_owner_question=lambda msg, **kw: {"answered": msg, **kw})
    return {"agent_cli": cli, "agent_team": team, "agent_router": router, "agent_review": review,
            "health_watchdog": watchdog, "code_index": code_index, "voice_bridge": voice}


class AgentsBridgeTests(_TmpRootCase):
    """jarvis_agents_bridge dispatch against fake modules in sys.modules."""

    def setUp(self):
        super().setUp()
        self.mods = _make_agent_fakes()
        patcher = mock.patch.dict(sys.modules, self.mods)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.saved_path = list(sys.path)

        def _restore_path():
            sys.path[:] = self.saved_path

        self.addCleanup(_restore_path)

    def bridge(self, args):
        return jrm.execute_tool("jarvis_agents_bridge", args)

    def test_list_progress_outbox_logs_and_stop(self):
        res = self.bridge({"action": "list"})
        self.assertEqual(res["ok"], True)
        self.assertEqual(res["agents"], 2)
        self.assertEqual(len(res["projects"]), 10)
        one = self.bridge({"action": "progress", "agent": "claude"})
        self.assertEqual(one, {"ok": True, "agent": "claude", "run": "x"})
        all_agents = self.bridge({"action": "progress"})
        self.assertEqual([a["agent"] for a in all_agents["agents"]], ["opus", "son"])
        box = self.bridge({"action": "outbox", "agent": "claude"})
        self.assertEqual(box["files"], {"aid": "claude", "files": ["a"]})
        log = self.bridge({"action": "logs", "agent": "claude"})
        self.assertEqual(log, {"ok": True, "agent": "claude", "log": "TAIL-claude"})
        stopped = self.bridge({"action": "stop", "agent": "claude"})
        self.assertEqual(stopped, {"stopped": "claude"})

    def test_run_background_direct_and_router_pick(self):
        direct = self.bridge({"action": "run_background", "agent": "opus", "task": "make tea", "target": "/tmp/x"})
        self.assertEqual(direct, {"started": "opus", "task": "make tea", "approved": True,
                                  "consent": "remote-mcp", "target_hint": "/tmp/x"})
        picked = self.bridge({"action": "run_background", "task": "pick for me"})
        self.assertEqual(picked["started"], "hermes")
        self.assertEqual(picked["consent"], "remote-mcp")
        self.assertTrue(picked["approved"])

    def test_team_start_wave_and_project_contracts(self):
        wave = self.bridge({"action": "team_start", "project_id": "W9",
                            "assignments": [{"a": 1}], "review_agent": "claude"})
        self.assertEqual(wave, {"wave": "w9", "assignments": [{"a": 1}], "review_agent": "claude",
                                "approved": True, "consent": "remote-mcp"})
        project = self.bridge({"action": "team_start", "task": "build it",
                               "participants": ["opus", "son"], "title": "T", "project_id": "pid1",
                               "architect_agent": "arch", "plan_first": True, "use_worktrees": False,
                               "max_total_runs": 3, "max_project_minutes": 7, "seed_dir": "sd"})
        expected = {"goal": "build it", "participants": ["opus", "son"],
                    "assignments": None, "title": "T", "project_id": "pid1",
                    "review_agent": "", "architect_agent": "arch",
                    "plan_first": True, "use_worktrees": False,
                    "max_total_runs": 3, "max_project_minutes": 7, "seed_dir": "sd",
                    "approved": True, "consent": "remote-mcp"}
        for key, value in expected.items():
            self.assertEqual(project[key], value, key)
        self.assertEqual(project["project"], "pid1")
        status = self.bridge({"action": "team_status", "project_id": "W9"})
        self.assertEqual(status, {"ok": True, "pid": "w9", "st": "running"})
        listing = self.bridge({"action": "team_list"})
        self.assertEqual(len(listing["projects"]), 5)

    def test_team_chat_nudge_and_support_actions(self):
        chat = self.bridge({"action": "team_chat", "project_id": "w9", "message": "hi"})
        self.assertTrue(chat["ok"])
        self.assertEqual(chat["posted"]["posted"]["text"], "hi")
        self.assertEqual(chat["posted"]["posted"]["to"], "all")
        self.assertEqual(chat["posted"]["posted"]["sender"], "owner")
        self.assertEqual(len(chat["messages"]), 30)
        read_only = self.bridge({"action": "team_chat", "project_id": "w9"})
        self.assertEqual(len(read_only["messages"]), 50)
        nudged = self.bridge({"action": "team_nudge", "project_id": "w9", "agent": "opus", "task": "go"})
        self.assertEqual(nudged, {"nudged": "opus", "approved": True, "consent": "remote-mcp"})
        self.assertEqual(self.bridge({"action": "team_stop", "project_id": "w9"}), {"stopped": "w9"})
        self.assertEqual(self.bridge({"action": "team_diff", "project_id": "w9", "target": "/tmp/t"}),
                         {"diff": "team:w9"})
        self.assertEqual(self.bridge({"action": "team_apply", "project_id": "w9"}), {"applied": "team:w9"})
        self.assertEqual(self.bridge({"action": "router"}), {"ok": True, "routes": 1})
        self.assertEqual(self.bridge({"action": "watchdog", "auto_repair": True, "target": "/tmp/z"}),
                         {"auto": True, "root": "/tmp/z"})
        self.assertEqual(self.bridge({"action": "context_search", "task": "find x", "target": "/tmp/y"}),
                         {"ok": True, "hits": {"q": "find x", "root": "/tmp/y"}})
        questions = self.bridge({"action": "owner_questions", "project_id": "w9"})
        self.assertEqual(questions, {"ok": True, "questions": ["q1"]})
        answer = self.bridge({"action": "owner_reply", "task": "yes", "req_id": "r1", "project_id": "w9"})
        self.assertEqual(answer["question"]["req_id"], "r1")
        self.assertEqual(answer["question"]["source"], "remote-mcp")
        self.assertEqual(self.bridge({"action": "rollback"}), {"rolled": str(self.root)})
        with self.assertRaises(ValueError) as ctx:
            self.bridge({"action": "explode-ray"})
        self.assertEqual(str(ctx.exception), "Nieznane narzędzie MCP: jarvis_agents_bridge")


CFG = {"secret_slug": "TEST-SLUG-42", "client_id": "cid-1", "client_secret": "csec-1", "signing_key": "KEY-9"}
ENV_KEYS = ("JARVIS_MCP_PUBLIC_URL", "JARVIS_MCP_PUBLIC_URL_FILE")


class _HandlerCase(TestCase):
    """Real ThreadingHTTPServer bound to 127.0.0.1:0 with isolated module state."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp())
        (cls.root / "pkg").mkdir()
        (cls.root / "pkg" / "mod.py").write_text('hello = "ja"\nworld = "rv"\n', encoding="utf-8")
        cls._saved_env = {k: os.environ.pop(k, None) for k in ENV_KEYS}
        cls._patchers = [
            mock.patch.object(jrm, "PROJECT_ROOT", cls.root),
            mock.patch.object(jrm, "CONFIG_DIR", Path(tempfile.mkdtemp())),
        ]
        for p in cls._patchers:
            p.start()

        class Handler(jrm.MCPBridgeHandler):
            auth_cfg = CFG.copy()

        cls.handler_cls = Handler
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls._saved_codes = dict(jrm._AUTH_CODES)
        jrm._AUTH_CODES.clear()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        for p in cls._patchers:
            p.stop()
        jrm._AUTH_CODES.clear()
        jrm._AUTH_CODES.update(cls._saved_codes)
        for key, value in cls._saved_env.items():
            if value is not None:
                os.environ[key] = value

    @property
    def base(self):
        return f"http://127.0.0.1:{self.__class__.port}"

    def _request(self, path, *, method="GET", data=None, headers=None):
        opener = urllib.request.build_opener(_NoRedirect())
        req = urllib.request.Request(self.base + path, data=data, headers=headers or {}, method=method)
        if data is not None and not isinstance(data, (bytes, bytearray)):
            req.add_header("Content-Type", "application/json")
        try:
            with opener.open(req, timeout=5) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HandlerCoreTests(_HandlerCase):
    """GET/DELETE health, discovery, RBAC gate and JSON-RPC dispatch."""

    def _post_json(self, path, payload, headers=None):
        body = json.dumps(payload).encode("utf-8")
        st, hd, raw = self._request(path, method="POST", data=body,
                                    headers={"Content-Type": "application/json", **(headers or {})})
        return st, hd, json.loads(raw) if raw else None

    def test_health_404_and_delete(self):
        st, _, raw = self._request("/health")
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(raw), {"ok": True, "service": "jarvis-remote-mcp", "project": str(self.root)})
        st, _, raw = self._request("/nope")
        self.assertEqual((st, json.loads(raw)), (404, {"error": "not_found"}))
        st, _, raw = self._request("/other", method="DELETE")
        self.assertEqual(st, 404)
        st, _, raw = self._request("/mcp", method="DELETE")
        self.assertEqual(st, 204)
        self.assertEqual(raw, b"")

    def test_well_known_and_authorize_form(self):
        st, _, raw = self._request(
            "/.well-known/oauth-authorization-server",
            headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "ex.com"})
        meta = json.loads(raw)
        self.assertEqual(st, 200)
        self.assertEqual(meta["issuer"], "https://ex.com")
        self.assertEqual(meta["authorization_endpoint"], "https://ex.com/oauth/authorize")
        self.assertEqual(meta["token_endpoint"], "https://ex.com/oauth/token")
        self.assertEqual(meta["grant_types_supported"], ["authorization_code", "client_credentials", "refresh_token"])
        st, _, raw = self._request("/oauth/authorize?client_id=WRONG&redirect_uri=https://cb/cb&state=xyz")
        self.assertEqual(st, 403)
        self.assertIn(b"Invalid client_id", raw)
        st, _, raw = self._request(
            "/oauth/authorize?client_id=cid-1&redirect_uri=https%3A%2F%2Fcb%2Fcb&state=st%20q")
        self.assertEqual(st, 200)
        self.assertIn(b"<input type='hidden' name='redirect_uri' value='https://cb/cb' />", raw)
        self.assertIn(b"<input type='hidden' name='state' value='st q' />", raw)

    def test_mcp_authorization_matrix(self):
        st, _, raw = self._request("/mcp")
        self.assertEqual((st, json.loads(raw)), (401, {"error": "unauthorized"}))
        st, _, raw = self._request("/mcp/WRONG-SLUG")
        self.assertEqual((st, json.loads(raw)), (401, {"error": "unauthorized"}))
        st, hd, _ = self._request("/mcp/TEST-SLUG-42")
        self.assertEqual(st, 405)
        self.assertEqual(hd.get("Allow"), "POST, DELETE")
        token = jrm._sign_token({"sub": "x", "exp": time.time() + 60}, CFG["signing_key"])
        for header in ("Bearer " + token, "bearer " + token, "Bearer " + CFG["secret_slug"], "Bearer wrong"):
            st, _, _ = self._request("/mcp", headers={"Authorization": header})
            expected = 401 if header == "Bearer wrong" else 405
            self.assertEqual(st, expected, header)
        # ścieżka z ukośnikiem końcowym też autoryzuje przez slug
        st, _, _ = self._request("/mcp/TEST-SLUG-42/", headers={"Authorization": "Bearer wrong"})
        self.assertEqual(st, 405)

    def test_rpc_initialize_ping_and_lists(self):
        st, hd, body = self._post_json("/mcp/TEST-SLUG-42",
                                       {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                        "params": {"protocolVersion": "1999-09-09"}})
        self.assertEqual(st, 200)
        self.assertEqual(body["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(body["result"]["serverInfo"], {"name": "jarvis-ubuntu-mcp", "version": "1.0.0"})
        sid = hd.get("Mcp-Session-Id")
        self.assertEqual(len(sid or ""), 32)
        token = jrm._sign_token({"sub": "x", "exp": time.time() + 60}, CFG["signing_key"])
        st, _, body = self._post_json("/mcp", {"jsonrpc": "2.0", "id": 2, "method": "initialize",
                                               "params": {"protocolVersion": "2025-06-18"}},
                                      headers={"Authorization": "Bearer " + token})
        self.assertEqual(body["result"]["protocolVersion"], "2025-06-18")
        st, _, body = self._post_json("/mcp/TEST-SLUG-42", {"jsonrpc": "2.0", "id": 3, "method": "ping"})
        self.assertEqual(body["id"], 3)
        self.assertEqual(body["result"], {})
        st, _, body = self._post_json("/mcp/TEST-SLUG-42", {"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
        tools = body["result"]["tools"]
        self.assertEqual(len(tools), 8)
        self.assertTrue(all("inputSchema" in t and "description" in t for t in tools))
        st, _, body = self._post_json("/mcp/TEST-SLUG-42", {"jsonrpc": "2.0", "id": 5, "method": "resources/list"})
        self.assertEqual(body["result"], {"resources": []})
        st, _, body = self._post_json("/mcp/TEST-SLUG-42", {"jsonrpc": "2.0", "id": 6, "method": "prompts/list"})
        self.assertEqual(body["result"], {"prompts": []})

    def test_rpc_errors_batches_and_notifications(self):
        st, _, raw = self._request("/mcp/TEST-SLUG-42", method="POST", data=b"{nope",
                                   headers={"Content-Type": "application/json"})
        self.assertEqual((st, json.loads(raw)["error"]["code"]), (400, -32700))
        self.assertIsNone(json.loads(raw)["id"])
        st, _, body = self._post_json("/mcp/TEST-SLUG-42", {"jsonrpc": "2.0", "id": 7, "method": "no/such"})
        self.assertEqual(body["error"], {"code": -32601, "message": "Method not found: no/such"})
        st, _, raw = self._request("/mcp/TEST-SLUG-42", method="POST",
                                   data=json.dumps({"jsonrpc": "2.0", "method": "ping"}).encode(),
                                   headers={"Content-Type": "application/json"})
        self.assertEqual((st, raw), (202, b""))
        batch = [{"jsonrpc": "2.0", "method": "ping"}, {"jsonrpc": "2.0", "id": 9, "method": "ping"}]
        st, _, body = self._post_json("/mcp/TEST-SLUG-42", batch)
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["id"], 9)
        st, _, raw = self._request("/mcp/TEST-SLUG-42", method="POST",
                                   data=json.dumps([{"jsonrpc": "2.0", "method": "ping"}]).encode(),
                                   headers={"Content-Type": "application/json"})
        self.assertEqual((st, raw), (202, b""))
        mixed = [5, {"jsonrpc": "2.0", "id": 10, "method": "ping"}]
        st, _, body = self._post_json("/mcp/TEST-SLUG-42", mixed)
        self.assertEqual(len(body), 2)
        self.assertEqual(body[0]["error"], {"code": -32600, "message": "Invalid Request"})
        self.assertEqual(body[1]["id"], 10)
        # pusty {} traktowany jako notyfikacja (brak id) -> znik z odpowiedzi
        st, _, body = self._post_json("/mcp/TEST-SLUG-42",
                                      [{}, {"jsonrpc": "2.0", "id": 11, "method": "ping"}])
        self.assertEqual([b["id"] for b in body], [11])
        st, _, raw = self._request("/mcp", method="POST",
                                   data=json.dumps({"jsonrpc": "2.0", "id": 12, "method": "ping"}).encode(),
                                   headers={"Content-Type": "application/json"})
        self.assertEqual((st, json.loads(raw)), (401, {"error": "unauthorized"}))

    def test_tools_call_success_and_error(self):
        st, _, body = self._post_json("/mcp/TEST-SLUG-42",
                                      {"jsonrpc": "2.0", "id": 21, "method": "tools/call",
                                       "params": {"name": "jarvis_read_file",
                                                  "arguments": {"path": "pkg/mod.py"}}})
        result = body["result"]
        self.assertFalse(result["isError"])
        payload = json.loads(result["content"][0]["text"])
        self.assertEqual(payload["shown_lines"], "1..2")
        st, _, body = self._post_json("/mcp/TEST-SLUG-42",
                                      {"jsonrpc": "2.0", "id": 22, "method": "tools/call",
                                       "params": {"name": "nope", "arguments": {}}})
        self.assertTrue(body["result"]["isError"])
        self.assertEqual(body["result"]["content"][0]["text"],
                         "Błąd wykonania nope: Nieznane narzędzie MCP: nope")
        st, _, body = self._post_json("/mcp/TEST-SLUG-42",
                                      {"jsonrpc": "2.0", "id": 23, "method": "tools/call",
                                       "params": {"name": "jarvis_read_file",
                                                  "arguments": {"path": "pkg/missing.py"}}})
        self.assertTrue(body["result"]["isError"])
        self.assertIn("Plik nie istnieje", body["result"]["content"][0]["text"])


class HandlerOAuthTests(_HandlerCase):
    """OAuth 2.0 authorize/token endpoints end-to-end."""

    def _form_post(self, path, body, headers=None):
        raw = body.encode("utf-8") if isinstance(body, str) else urllib.parse.urlencode(body).encode()
        return self._request(path, method="POST", data=raw,
                             headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or {})})

    def _fetch_code(self, redirect_uri="https://cb/cb", state=""):
        form = "secret=csec-1&redirect_uri=" + urllib.parse.quote(redirect_uri, safe="")
        if state:
            form += "&state=" + urllib.parse.quote(state, safe="")
        st, hd, _ = self._form_post("/oauth/authorize", form)
        self.assertEqual(st, 302)
        return hd.get("Location", "")

    def _exchange(self, code, **extra):
        params = {"grant_type": "authorization_code", "code": code,
                  "client_id": "cid-1", "client_secret": "csec-1"}
        params.update(extra)
        return self._form_post("/oauth/token", params)

    def test_authorize_post_redirect_and_bad_secret(self):
        location = self._fetch_code(redirect_uri="https://cb/cb", state="st1")
        self.assertTrue(location.startswith("https://cb/cb?code="))
        self.assertIn("state=st1", location)
        location = self._fetch_code(redirect_uri="https://cb/cb?page=1")
        self.assertIn("page=1&code=", location)
        st, _, raw = self._form_post("/oauth/authorize", "secret=WRONG&redirect_uri=https%3A%2F%2Fcb%2Fcb")
        self.assertEqual(st, 403)
        self.assertIn("Błędny Client Secret", raw.decode("utf-8"))

    def test_token_exchange_full_flow(self):
        code = self._fetch_code().split("code=")[1]
        st, _, raw = self._exchange(code)
        self.assertEqual(st, 200)
        body = json.loads(raw)
        self.assertEqual(body["token_type"], "Bearer")
        self.assertEqual(body["expires_in"], 2592000)
        self.assertEqual(body["scope"], "mcp")
        self.assertTrue(jrm._verify_token(body["access_token"], CFG["signing_key"]))
        self.assertTrue(jrm._verify_token(body["refresh_token"], CFG["signing_key"]))
        padded = body["access_token"].split(".")[0] + "=="
        self.assertEqual(json.loads(base64.urlsafe_b64decode(padded))["sub"], "jarvis-owner")

    def test_token_replay_expired_and_wrong_client(self):
        code = self._fetch_code().split("code=")[1]
        st, _, raw = self._exchange(code)
        self.assertEqual(st, 200)
        st, _, raw = self._exchange(code)
        self.assertEqual((st, json.loads(raw)), (400, {"error": "invalid_grant"}))
        with jrm._LOCK:
            jrm._AUTH_CODES["dead-code"] = time.time() - 1
        st, _, raw = self._exchange("dead-code")
        self.assertEqual((st, json.loads(raw)), (400, {"error": "invalid_grant"}))
        st, _, raw = self._request(
            "/oauth/token", method="POST",
            data=urllib.parse.urlencode({"grant_type": "authorization_code", "code": "x",
                                         "client_id": "bad", "client_secret": "bad"}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual((st, json.loads(raw)), (401, {"error": "invalid_client"}))

    def test_token_grants_auth_and_content_type_variants(self):
        st, _, raw = self._form_post("/oauth/token", {"grant_type": "refresh_token",
                                                      "client_id": "cid-1", "client_secret": "csec-1"})
        self.assertEqual(st, 200)
        self.assertIn("access_token", json.loads(raw))
        basic = base64.b64encode(b"cid-1:csec-1").decode()
        st, _, raw = self._request(
            "/oauth/token", method="POST", data=json.dumps({"grant_type": "client_credentials"}).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Basic " + basic})
        self.assertEqual(st, 200)
        self.assertIn("access_token", json.loads(raw))
        bad_basic = base64.b64encode(b"x:y").decode()
        st, _, raw = self._request(
            "/oauth/token", method="POST", data=b"{not-json",
            headers={"Content-Type": "application/json", "Authorization": "Basic " + bad_basic})
        self.assertEqual((st, json.loads(raw)), (401, {"error": "invalid_client"}))
        st, _, raw = self._request("/oauth/token", method="POST", data=b"{bad",
                                   headers={"Content-Type": "application/json"})
        self.assertEqual((st, json.loads(raw)), (401, {"error": "invalid_client"}))


class BannerMainTests(TestCase):
    """print_banner and main(--show-auth) with fully isolated config paths."""

    def test_banner_contents(self):
        auth = {"secret_slug": "S1", "client_id": "cid", "client_secret": "cs"}
        buf = io.StringIO()
        with redirect_stdout(buf):
            jrm.print_banner(auth, "127.0.0.1", 9000, "https://tun.example")
        lines = buf.getvalue().splitlines()
        self.assertEqual(len(lines), 17)
        self.assertEqual(lines[1].strip(),
                         "JARVIS CUSTOM MCP SERVER — GOTOWY DO PODPIĘCIA W business.gemini.google")
        self.assertEqual(lines[3], " Lokalny adres nasłuchu : http://127.0.0.1:9000")
        self.assertTrue(lines[4].startswith(" Chroniony katalog      : "))
        self.assertEqual(lines[7].strip(), "MCP Server URL : https://tun.example/mcp/S1")
        self.assertEqual(lines[10].strip(), "MCP Server URL : https://tun.example/mcp")
        self.assertEqual(lines[11].strip(), "Client ID      : cid")
        self.assertEqual(lines[12].strip(), "Client Secret  : cs")
        self.assertEqual(lines[13].strip(), "Auth URL       : https://tun.example/oauth/authorize")
        self.assertEqual(lines[14].strip(), "Token URL      : https://tun.example/oauth/token")
        self.assertEqual(lines[15].strip(), "Scopes         : mcp")
        self.assertEqual(lines[16], "=" * 72)
        buf = io.StringIO()
        with redirect_stdout(buf):
            jrm.print_banner({"secret_slug": "S2", "client_id": "cid", "client_secret": "cs"},
                             "0.0.0.0", 8080)
        default_lines = buf.getvalue().splitlines()
        self.assertEqual(default_lines[7].strip(), "MCP Server URL : https://TWOJA-DOMENA-TUNELU/mcp/S2")

    def test_main_show_auth(self):
        cfg_dir = Path(tempfile.mkdtemp())
        root = Path(tempfile.mkdtemp())
        argv = ["jarvis_remote_mcp.py", "--show-auth", "--host", "127.0.0.1", "--port", "9999"]
        with mock.patch.object(jrm, "CONFIG_DIR", cfg_dir), \
                mock.patch.object(jrm, "AUTH_CONFIG_PATH", cfg_dir / "remote-mcp-auth.json"), \
                mock.patch.object(jrm, "PROJECT_ROOT", root), mock.patch.object(sys, "argv", argv):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = jrm.main()
        self.assertEqual(rc, 0)
        self.assertIn(" MCP Server URL :", buf.getvalue())
        self.assertIn("/mcp/", buf.getvalue())
        cfg_file = cfg_dir / "remote-mcp-auth.json"
        self.assertTrue(cfg_file.is_file())
        self.assertEqual(oct(cfg_file.stat().st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
