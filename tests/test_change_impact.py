"""Unit tests for `change_impact.py` — SRI verification/repair, git porcelain, blast radius.

Dotąd funkcje pokryte wybiórczo: wave8 happy-path analizy + LIVE fix=True na REPO_ROOT
(wave8/10/12), mission_routes wyłącznie mocki dispatchera. ZERO testów: `compute_sha384_sri`
wprost, `git_changed_files` (parsowanie porcelain, rename, cudzysłowy, skip backupów),
krawędzie SRI (missing_file z fixem, ucieczka z viewer/, CDN, brak index.html),
drabina ryzyka (server pośredni >=8/3 modułów), selekcja testów viewer/ui/wave.
Wszystko na fałszywym projekcie w świeżym tmp (repo niewymuszane).
"""
from __future__ import annotations

import base64
import hashlib
import subprocess
import sys
import unittest
from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp

sys.path.insert(0, ".")

import change_impact as ci  # noqa: E402

KNOWN_SRI_PREFIX = "sha384-"


class FakeProjectBase(unittest.TestCase):
    """Projekt: a <- b <- c <- server, test_a/test_b (importy), test_c izolowany, viewer."""

    def setUp(self) -> None:
        self.base = Path(mkdtemp())
        self.addCleanup(rmtree, self.base, True)
        self.root = self.base / "proj"
        (self.root / "tests").mkdir(parents=True)
        (self.root / "viewer").mkdir()
        for rel, content in {
            "a.py": "A = 1\n",
            "b.py": "import a\nB = 2\n",
            "c.py": "import b\nC = 3\n",
            "server.py": "import c\nrun = 4\n",
            "tests/test_a.py": "import a\n",
            "tests/test_b.py": "from b import B\n",
            "tests/test_c.py": "x = 1\n",               # zaden import — nieuBoolwany przy analizach
            "tests/test_viewer_ui.py": "y = 1\n",        # nazwa zawiera viewer
            "viewer/app.js": "console.log(1)\n",
        }.items():
            (self.root / rel).write_text(content, encoding="utf-8")

    def _write_index(self, src: str, integrity: str) -> None:
        tag = f'<script src="{src}" integrity="{integrity}"></script>'
        (self.root / "viewer" / "index.html").write_text(
            f"<html><head>{tag}</head></html>", encoding="utf-8")


class ComputeSha384Tests(FakeProjectBase):
    def test_digest_format_matches_reference_computation(self):
        asset = self.root / "viewer" / "app.js"
        expected = KNOWN_SRI_PREFIX + base64.b64encode(hashlib.sha384(asset.read_bytes()).digest()).decode()
        self.assertEqual(ci.compute_sha384_sri(asset), expected)

    def test_different_content_different_digest(self):
        (self.root / "x1.js").write_text("a", encoding="utf-8")
        (self.root / "x2.js").write_text("b", encoding="utf-8")
        self.assertNotEqual(ci.compute_sha384_sri(self.root / "x1.js"),
                            ci.compute_sha384_sri(self.root / "x2.js"))
        for digest in (ci.compute_sha384_sri(self.root / "x1.js"),
                       ci.compute_sha384_sri(self.root / "x2.js")):
            self.assertTrue(digest.startswith(KNOWN_SRI_PREFIX))


class SyncViewerSriTests(FakeProjectBase):
    def test_missing_index_reports_not_present(self):
        res = ci.sync_viewer_sri(self.base / "pusty")
        self.assertEqual(res, {"ok": True, "present": False, "checked_tags": 0,
                               "mismatches": [], "updated": 0})

    def test_matching_hashes_clean_with_query_and_fragment(self):
        sri = ci.compute_sha384_sri(self.root / "viewer" / "app.js")
        self._write_index("app.js?v=3#x", sri)
        res = ci.sync_viewer_sri(self.root)
        self.assertTrue(res["ok"])
        self.assertTrue(res["present"])
        self.assertEqual(res["checked_tags"], 1)
        self.assertEqual(res["mismatches"], [])
        self.assertEqual(res["updated"], 0)

    def test_stale_hash_detected_and_fixed_atomically(self):
        self._write_index("app.js", "sha384-WRONGHASH==")
        res = ci.sync_viewer_sri(self.root, fix=False)
        self.assertFalse(res["ok"])
        self.assertEqual(res["checked_tags"], 1)
        mismatch = res["mismatches"][0]
        self.assertEqual(mismatch["asset"], "app.js")
        self.assertEqual(mismatch["declared"], "sha384-WRONGHASH==")
        self.assertEqual(mismatch["actual"], ci.compute_sha384_sri(self.root / "viewer" / "app.js"))
        self.assertEqual(res["updated"], 0)
        # fix=True naprawia plik w miejscu
        res2 = ci.sync_viewer_sri(self.root, fix=True)
        self.assertTrue(res2["ok"])
        self.assertEqual(res2["updated"], 1)
        self.assertTrue(ci.sync_viewer_sri(self.root)["ok"])

    def test_missing_asset_not_repairable_even_with_fix(self):
        self._write_index("gone.js", "sha384-ANY")
        res = ci.sync_viewer_sri(self.root, fix=True)
        self.assertFalse(res["ok"])                       # updated(0) != mismatches(1)
        self.assertEqual(res["checked_tags"], 0)          # brak pliku nie liczy sie do checked
        self.assertEqual(res["mismatches"], [{"asset": "gone.js", "reason": "missing_file"}])
        self.assertEqual(res["updated"], 0)

    def test_outside_viewer_and_remote_urls_ignored(self):
        self._write_index("../evil.js", "sha384-ANY")
        (self.root / "viewer" / "index.html").write_text(
            '<script src="../evil.js" integrity="sha384-A"></script>'
            '<link href="https://cdn.example/x.css" integrity="sha384-B">'
            '<script src="/viewer/app.js" integrity="CREATED-LATER-OK"></script>',
            encoding="utf-8")
        res = ci.sync_viewer_sri(self.root)               # taki integrity nie jest sha384- -> tag zignorowany
        self.assertEqual(res["checked_tags"], 0)
        self.assertEqual(res["mismatches"], [])

    def test_absolute_viewer_path_resolves_to_root(self):
        sri = ci.compute_sha384_sri(self.root / "viewer" / "app.js")
        (self.root / "viewer" / "index.html").write_text(
            f'<script src="/viewer/app.js" integrity="{sri}"></script>', encoding="utf-8")
        res = ci.sync_viewer_sri(self.root)
        self.assertEqual(res["checked_tags"], 1)
        self.assertTrue(res["ok"])


class GitChangedFilesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = Path(mkdtemp())
        self.addCleanup(rmtree, self.base, True)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        for cmd in (["git", "init", "-q"], ["git", "config", "user.email", "t@t"],
                    ["git", "config", "user.name", "t"]):
            subprocess.run(cmd, cwd=self.repo, check=True, capture_output=True)
        (self.repo / "f1.txt").write_text("x", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=self.repo, check=True, capture_output=True)

    def test_no_git_directory_returns_empty(self):
        plain = self.base / "plain"
        plain.mkdir()
        self.assertEqual(ci.git_changed_files(plain), [])

    def test_porcelain_rename_untracked_and_backup_skip(self):
        subprocess.run(["git", "mv", "f1.txt", "renamed.txt"], cwd=self.repo,
                       check=True, capture_output=True)
        (self.repo / "f2 new.txt").write_text("n", encoding="utf-8")     # nowy, spacja w nazwie
        (self.repo / ".jarvis-mcp-backups").mkdir()
        (self.repo / ".jarvis-mcp-backups" / "z.bak").write_text("b", encoding="utf-8")
        changed = ci.git_changed_files(self.repo)
        self.assertIn("renamed.txt", changed)       # rename parsowany jako NOWA nazwa
        self.assertIn("f2 new.txt", changed)
        self.assertTrue(all(c != "f1.txt" for c in changed))
        self.assertFalse(any(".jarvis-mcp-backups" in c for c in changed))


class AnalyzeBlastRadiusTests(FakeProjectBase):
    def test_two_hop_dependents_with_medium_risk(self):
        res = ci.analyze_blast_radius(self.root, changed_files=["a.py"])
        self.assertTrue(res["ok"])
        self.assertEqual(res["changed_files"], ["a.py"])
        self.assertEqual(res["affected_modules"], ["a.py", "b.py", "c.py"])
        self.assertEqual(res["selected_tests"], ["tests/test_a.py", "tests/test_b.py"])
        self.assertEqual(res["total_test_suites"], 4)          # test_a/test_b/test_c/test_viewer_ui
        self.assertEqual(res["blast_risk"], "medium")          # 3 nie-testowe moduly
        self.assertFalse(res["sri"]["present"])                # fixture bez index.html

    def test_indirect_server_dependency_is_high_risk(self):
        """"c.py" poprawia "server.py" (1 hop) -> napis "server.py" w affected => high."""
        res = ci.analyze_blast_radius(self.root, changed_files=["c.py"])
        self.assertEqual(res["blast_risk"], "high")
        self.assertIn("server.py", res["affected_modules"])

    def test_direct_server_change_high_risk_without_test_impact(self):
        res = ci.analyze_blast_radius(self.root, changed_files=["server.py"])
        self.assertEqual(res["blast_risk"], "high")
        self.assertEqual(res["affected_modules"], ["server.py"])
        self.assertEqual(res["selected_tests"], [])

    def test_isolated_module_low_risk(self):
        # d.py nic nie importuje i nikim nie importowany
        (self.root / "d.py").write_text("D = 5\n", encoding="utf-8")
        res = ci.analyze_blast_radius(self.root, changed_files=["d.py"])
        self.assertEqual(res["affected_modules"], ["d.py"])
        self.assertEqual(res["blast_risk"], "low")
        self.assertEqual(res["selected_tests"], [])

    def test_viewer_seed_selects_viewer_ui_and_wave_tests(self):
        res = ci.analyze_blast_radius(self.root, changed_files=["viewer/app.js"])
        self.assertEqual(res["selected_tests"], ["tests/test_viewer_ui.py"])
        self.assertEqual(res["blast_risk"], "low")     # viewer/* nie w non_test? -> affected tylko seed
        self.assertEqual(res["changed_files"], ["viewer/app.js"])

    def test_source_prefix_stripped_from_seeds(self):
        res = ci.analyze_blast_radius(self.root, changed_files=["./a.py"])
        self.assertEqual(res["changed_files"], ["a.py"])

    def test_sri_snapshot_embedded_in_result(self):
        sri = ci.compute_sha384_sri(self.root / "viewer" / "app.js")
        self._write_index("app.js", sri)
        res = ci.analyze_blast_radius(self.root, changed_files=["a.py"])
        self.assertEqual(res["sri"]["ok"], True)
        self.assertEqual(res["sri"]["checked_tags"], 1)

    def test_pragmatic_sri_mismatch_fails_blast_result_ok_but_sri_flagged(self):
        self._write_index("app.js", "sha384-STALE==")
        res = ci.analyze_blast_radius(self.root, changed_files=["a.py"])
        self.assertTrue(res["ok"])                     # analizy ok niezaleznie od SRI
        self.assertFalse(res["sri"]["ok"])
        self.assertEqual(res["sri"]["mismatches"][0]["asset"], "app.js")


if __name__ == "__main__":
    unittest.main()
