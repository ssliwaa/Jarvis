"""Unit tests for `security_scanner.py` — AST sinks, secret patterns, directory walk filters.

Dotąd funkcje `scan_python_ast` / `scan_text_secrets` istniały w suite'ach wyłącznie
pośrednio (jeden happy-path `scan_directory` w test_wave3). Tu testujemy każdą
funkcję jako jednostkę + krawędzie przechadzki po drzewie (skip-listy, symlinki,
oversize, cap 50 findings). Dywajsy są syntetyczne (budowane w locie), więc same
źródła testów nie trafiają pod wzorce sekretów.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, ".")

import security_scanner as ss  # noqa: E402

FAKE_ANT = "sk-ant-api03-" + ("A" * 28)
FAKE_OPENAI = "sk-proj-" + ("O" * 25)
FAKE_AIZA = "AIzaSy" + ("G" * 33)
FAKE_GHP = "ghp_" + ("H" * 31)
FAKE_GROQ = "gsk_" + ("Q" * 30)
FAKE_TG = "123456789:AA" + ("T" * 32)
FAKE_PEM = "-----BEGIN RSA PRIVATE KEY-----"
BUTLER_LINE = "subprocess.run(cmd, shell=True)"


class ScanPythonAstTests(unittest.TestCase):
    def _kinds(self, source: str) -> set[str]:
        return {f["kind"] for f in ss.scan_python_ast("x.py", source)}

    def test_shell_true_hooks_and_lineno(self):
        src = (
            "import subprocess\n"
            "subprocess.run(['ls'])\n"          # brak shell -> czyste
            f"{BUTLER_LINE}\n"                 # shell=True -> flaga
            "subprocess.check_output(c, shell=True)\n"
            "subprocess.Popen(c, shell=True)\n"
            "subprocess.call(c, shell=None)\n"  # shell=None -> czyste
        )
        shells = [f for f in ss.scan_python_ast("p.py", src) if f["kind"] == "ast_shell_true"]
        self.assertEqual([f["line"] for f in shells], [3, 4, 5])
        self.assertTrue(all(f["severity"] == "high" for f in shells))
        self.assertTrue(all(f["path"] == "p.py" for f in shells))
        self.assertTrue(all("shell=True" in f["detail"] for f in shells))

    def test_os_system_and_deserializers(self):
        kinds = self._kinds(
            "import os, pickle, marshal\n"
            "os.system('ls')\n"
            "pickle.loads(b'x')\n"
            "marshal.load(f)\n"
        )
        self.assertEqual(kinds, {"ast_os_system", "ast_pickle_loads", "ast_marshal_loads"})

    def test_yaml_load_distinguishes_loader_argument(self):
        src = (
            "import yaml\n"
            "yaml.load(s)\n"
            "yaml.load(s, Loader=yaml.SafeLoader)\n"
            "yaml.safe_load(s)\n"
        )
        findings = [f for f in ss.scan_python_ast("y.py", src) if f["kind"] == "ast_yaml_unsafe_load"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 2)
        self.assertIn("SafeLoader", findings[0]["detail"])

    def test_syntax_error_returns_no_findings(self):
        self.assertEqual(ss.scan_python_ast("broken.py", "def f(:\n  pass\n"), [])

    def test_bare_import_escape_is_documented_limit(self):
        """`from subprocess import run` + shell=True NIE jest flagowane (qualname bez modulu)."""
        kinds = self._kinds("from subprocess import run\nrun(cmd, shell=True)\n")
        self.assertEqual(kinds, set())


class ScanTextSecretsTests(unittest.TestCase):
    def test_all_seven_patterns_detected_critical_and_masked(self):
        lines = [
            f'ANT = "{FAKE_ANT}"',
            f'OPEN = "{FAKE_OPENAI}"',
            f'GOOG = "{FAKE_AIZA}"',
            f'GH = "{FAKE_GHP}"',
            f'GROQ = "{FAKE_GROQ}"',
            f'TG = "{FAKE_TG}"',
            f'PEM = "{FAKE_PEM}"',
        ]
        findings = ss.scan_text_secrets("s.py", "\n".join(lines))
        self.assertEqual({f["kind"] for f in findings}, {
            "secret_anthropic_key", "secret_openai_key", "secret_google_api_key",
            "secret_github_pat", "secret_groq_key", "secret_telegram_bot_token",
            "secret_private_key_pem",
        })
        self.assertTrue(all(f["severity"] == "critical" for f in findings))
        self.assertEqual([f["line"] for f in findings], [1, 2, 3, 4, 5, 6, 7])
        joined = " ".join(f["detail"] for f in findings)
        for secret in (FAKE_ANT, FAKE_OPENAI, FAKE_AIZA, FAKE_GHP, FAKE_GROQ, FAKE_TG):
            self.assertNotIn(secret, joined)
        self.assertIn(FAKE_ANT[:6], joined)  # mask pokazuje tylko prefiks

    def test_suppression_directive_skips_line(self):
        text = f'ANT = "{FAKE_ANT}"  # jarvis-sec:ignore\nGH = "{FAKE_GHP}"\n'
        findings = ss.scan_text_secrets("s.py", text)
        self.assertEqual([f["kind"] for f in findings], ["secret_github_pat"])

    def test_clean_text_yields_nothing(self):
        self.assertEqual(ss.scan_text_secrets("s.py", "print('cześć')\nx = 123\n"), [])

    def test_mask_match_boundaries(self):
        self.assertEqual(ss._mask_match("kr0tk1"), "***")
        self.assertEqual(ss._mask_match("0123456789"), "***")
        self.assertEqual(ss._mask_match("0123456789A"), "012345…89A")


class ScanDirectoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _write(self, rel: str, content: str) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_missing_directory_error_shape(self):
        res = ss.scan_directory(self.root / "nie-ma")
        self.assertFalse(res["ok"])
        self.assertEqual(res["scanned_files"], 0)
        self.assertEqual(res["findings"], [])
        self.assertTrue(str(res["error"]).startswith("Brak katalogu"))
        self.assertNotIn("findings_count", res)  # brak w error branchu

    def test_walk_filters_and_relative_paths(self):
        self._write("app.py", f"import os\nos.system('ls')\nK = '{FAKE_ANT}'\n")
        self._write("test_helper.py", f"K = '{FAKE_GHP}'\n")                       # test_* pomijany
        self._write("tests/unit_x.py", f"K = '{FAKE_GROQ}'\n")                     # katalog tests pomijany
        self._write("node_modules/deps/index.js", f"K = '{FAKE_TG}'\n")            # SKIP_DIRS
        self._write(".jarvis-cache/state.py", f"K = '{FAKE_GHP}'\n")               # prefix .jarvis-*
        self._write("config.yaml", "a: 1\n")                                      # czysty
        res = ss.scan_directory(self.root)

        self.assertEqual(res["scanned_files"], 2)  # app.py + config.yaml
        self.assertFalse(res["ok"])
        kinds = {(f["kind"], f["path"]) for f in res["findings"]}
        self.assertEqual(kinds, {("ast_os_system", "app.py"), ("secret_anthropic_key", "app.py")})

    def test_include_tests_true_scans_test_files_and_dirs(self):
        self._write("test_a.py", f"K = '{FAKE_GHP}'\n")
        self._write("tests/unit_x.py", f"K = '{FAKE_GROQ}'\n")
        self.assertEqual(ss.scan_directory(self.root, include_tests=True)["scanned_files"], 2)
        self.assertEqual(ss.scan_directory(self.root)["scanned_files"], 0)

    def test_symlink_oversize_and_unknown_suffix_skipped(self):
        target = self.root / "real.py"
        target.write_text(f"K = '{FAKE_ANT}'\n", encoding="utf-8")
        link = self.root / "linked.py"
        link.symlink_to(target)
        oversize = self._write("wielki.py", "x" * (ss.MAX_SCAN_BYTES + 1))
        self.assertGreater(oversize.stat().st_size, ss.MAX_SCAN_BYTES)
        self._write("blob.pyc", f"K = '{FAKE_GHP}'\n")  # .pyc poza SCAN_SUFFIXES
        res = ss.scan_directory(self.root)
        self.assertEqual(res["scanned_files"], 1)  # tylko real.py
        self.assertTrue(res["findings"])

    def test_clean_tree_ok_true(self):
        self._write("main.py", "print('ok')\n")
        res = ss.scan_directory(self.root)
        self.assertTrue(res["ok"])
        self.assertEqual(res["findings_count"], 0)
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["scanned_files"], 1)

    def test_findings_capped_at_50_with_full_count(self):
        self._write("leak.py", "\n".join(f"K{i} = '{FAKE_ANT}{i}'" for i in range(51)))
        res = ss.scan_directory(self.root)
        self.assertEqual(res["findings_count"], 51)
        self.assertEqual(len(res["findings"]), 50)
        self.assertFalse(res["ok"])

    def test_constants_guard_size_limits(self):
        self.assertEqual(ss.MAX_SCAN_BYTES, 350_000)
        self.assertEqual(ss.MAX_SCAN_FILES, 1500)
        self.assertIn(".py", ss.SCAN_SUFFIXES)
        self.assertIn(".git", ss.SKIP_DIRS)


if __name__ == "__main__":
    unittest.main()
