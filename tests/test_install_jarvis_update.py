"""Self-extracting installer contracts: SHA-256 gate, archive manifest,
operator_tools merge and safe extraction with timestamped backups."""
import io
import sys
import tempfile
import zipfile
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest import TestCase, mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import install_jarvis_update as installer

EXPECTED_NAMES = {
    "atomic_io.py",
    "router.py",
    "plan_files.py",
    "operator_schedule.py",
    "operator_tools_sections_1_to_3.py",
    "operator_modules/vault_health.py",
    "operator_modules/reminders.py",
    "operator_modules/watch_pages.py",
    "operator_modules/email_agent.py",
    "operator_modules/media_control.py",
    "operator_modules/system_status.py",
    "operator_modules/workspace_context.py",
    "scripts/jarvis-mcp-public.sh",
    "scripts/install-stt.sh",
}

BACKUP_NAMES = EXPECTED_NAMES - {"operator_tools_sections_1_to_3.py"}


@contextmanager
def _capture_main(argv, stamp=None):
    buf = io.StringIO()
    with redirect_stdout(buf):
        if stamp is None:
            rc = installer.main(argv)
        else:
            with mock.patch.object(installer.time, "time", lambda: stamp):
                rc = installer.main(argv)
    yield rc, buf.getvalue()


class ArchiveTests(TestCase):
    def test_archive_bytes_decodes_to_verified_zip(self):
        payload = installer._archive_bytes()
        self.assertEqual(len(payload), 84599)
        self.assertEqual(payload[:2], b"PK")
        import hashlib
        self.assertEqual(hashlib.sha256(payload).hexdigest(), installer.EXPECTED_SHA256)
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            self.assertEqual(set(zf.namelist()), EXPECTED_NAMES)

    def test_payload_hash_mismatch_raises(self):
        with mock.patch.object(installer, "EXPECTED_SHA256", "deadbeef"):
            with self.assertRaises(RuntimeError) as ctx:
                installer._archive_bytes()
        self.assertEqual(
            str(ctx.exception),
            "Niezgodność sumy kontrolnej SHA-256: oczekiwano deadbeef, "
            "otrzymano e80b5e8404deeb502d2de8130fb68fcc20d7074bdbec18d7244ded6e36cd13a4")

    def test_archive_manifest_and_script_attributes(self):
        payload = installer._archive_bytes()
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            infos = {i.filename: i for i in zf.infolist()}
            self.assertEqual(infos["router.py"].file_size, 45766)
            self.assertEqual(infos["operator_tools_sections_1_to_3.py"].file_size, 52516)
            for sh in ("scripts/jarvis-mcp-public.sh", "scripts/install-stt.sh"):
                self.assertEqual(oct((infos[sh].external_attr >> 16) & 0o777), "0o755")


class MergeOperatorToolsTests(TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.backup = self.root / ".backup"

    def test_merge_skips_without_patch(self):
        (self.root / "operator_tools.py").write_text("A = 1\n", encoding="utf-8")
        self.assertEqual(installer._merge_operator_tools(self.root, self.backup),
                         "pominięto (brak pliku łatki)")

    def test_merge_skips_without_original_keeping_patch(self):
        (self.root / "operator_tools_sections_1_to_3.py").write_text("X = 1\n", encoding="utf-8")
        self.assertEqual(
            installer._merge_operator_tools(self.root, self.backup),
            "pominięto (brak operator_tools.py w katalogu docelowym; "
            "pozostawiono operator_tools_sections_1_to_3.py)")
        self.assertTrue((self.root / "operator_tools_sections_1_to_3.py").is_file())

    def test_merge_skips_without_section_boundary(self):
        (self.root / "operator_tools.py").write_text("A = 1\nB = 2\n", encoding="utf-8")
        (self.root / "operator_tools_sections_1_to_3.py").write_text("NEW = 3\n", encoding="utf-8")
        self.assertEqual(installer._merge_operator_tools(self.root, self.backup),
                         "pominięto (nie znaleziono granicy sekcji 3 w operator_tools.py)")
        self.assertEqual((self.root / "operator_tools.py").read_text(encoding="utf-8"), "A = 1\nB = 2\n")

    def test_merge_happy_path_replaces_head_and_keeps_tail(self):
        orig = self.root / "operator_tools.py"
        orig.write_text(
            '# head\nclass A:\n    def f(self):\n'
            '        return {"truncated": len(raw) >= 1_000_000}\n'
            '# sekcja 4 nizej\nX = 9\n',
            encoding="utf-8")
        (self.root / "operator_tools_sections_1_to_3.py").write_text(
            "NEW_HEAD = 7\nclass NewSection:\n    value = 1\n", encoding="utf-8")
        message = installer._merge_operator_tools(self.root, self.backup)
        self.assertEqual(message, "połączono pomyślnie (6 linii)")
        self.assertEqual(
            orig.read_text(encoding="utf-8"),
            "NEW_HEAD = 7\nclass NewSection:\n    value = 1\n\n# sekcja 4 nizej\nX = 9\n")
        self.assertTrue((self.backup / "operator_tools.py").is_file())
        self.assertFalse((self.root / "operator_tools_sections_1_to_3.py").exists())


class MainTests(TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_zip_only_writes_verified_archive(self):
        target = self.tmp / "nested" / "out"
        with _capture_main(["--zip-only", str(target)]) as (rc, output):
            pass
        self.assertEqual(rc, 0)
        out_zip = target / "jarvis-aktualizacja-final.zip"
        self.assertTrue(target.is_dir())
        payload = installer._archive_bytes()
        self.assertEqual(out_zip.read_bytes(), payload)
        self.assertEqual(
            output.strip(),
            f"[OK] Zapisano archiwum: {out_zip} ({len(payload)} bajtów, SHA-256 zweryfikowane).")

    def test_full_install_into_fresh_dir(self):
        with _capture_main([str(self.tmp)]) as (rc, output):
            pass
        self.assertEqual(rc, 0)
        files = sorted(str(p.relative_to(self.tmp)) for p in self.tmp.rglob("*") if p.is_file())
        self.assertEqual(files, sorted(EXPECTED_NAMES))
        self.assertFalse((self.tmp / "operator_tools.py").exists())
        for sh in ("scripts/jarvis-mcp-public.sh", "scripts/install-stt.sh"):
            self.assertEqual(oct((self.tmp / sh).stat().st_mode & 0o777), "0o755")
        lines = output.strip().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0], f"[OK] Rozpakowano 14 finalnych plików do: {self.tmp}")
        self.assertEqual(lines[1], "[OK] Scalanie operator_tools.py: pominięto "
                                 "(brak operator_tools.py w katalogu docelowym; "
                                 "pozostawiono operator_tools_sections_1_to_3.py)")
        self.assertEqual(lines[2], "[GOTOWE] Uruchom `./scripts/check.sh` w katalogu projektu Jarvis.")
        self.assertEqual([p.name for p in self.tmp.iterdir() if p.name.startswith(".jarvis-backup-")], [])

    def test_second_install_makes_timestamped_backup(self):
        with _capture_main([str(self.tmp)]) as _:
            pass
        with _capture_main([str(self.tmp)], stamp=23456) as (rc, output):
            pass
        self.assertEqual(rc, 0)
        backup_dir = self.tmp / ".jarvis-backup-23456"
        self.assertTrue(backup_dir.is_dir())
        backed = sorted(str(p.relative_to(backup_dir)) for p in backup_dir.rglob("*") if p.is_file())
        self.assertEqual(backed, sorted(BACKUP_NAMES))
        lines = output.strip().splitlines()
        self.assertEqual(len(lines), 4)
        self.assertEqual(lines[2], f"[OK] Kopia zapasowa poprzednich plików: {backup_dir}")
        self.assertEqual(lines[3], "[GOTOWE] Uruchom `./scripts/check.sh` w katalogu projektu Jarvis.")

    def test_unsafe_archive_paths_are_rejected(self):
        class FakeInfo:
            def __init__(self, name):
                self.filename = name
                self.external_attr = 0

        class FakeZF:
            def __init__(self, names):
                self.names = names

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def infolist(self):
                return [FakeInfo(n) for n in self.names]

            def read(self, name):
                return b"X"

        def _factory(bad):
            def _make(*args, **kwargs):
                return FakeZF([bad])
            return _make

        cases = (
            ("/etc/pwned", "Niebezpieczna ścieżka w archiwum: /etc/pwned"),
            ("a/../../b/pwned", "Niebezpieczna ścieżka w archiwum: a/../../b/pwned"),
        )
        for bad, expected in cases:
            with mock.patch.object(installer.zipfile, "ZipFile", _factory(bad)):
                with self.assertRaises(RuntimeError) as ctx:
                    installer.main([str(self.tmp)])
            self.assertEqual(str(ctx.exception), expected)
        self.assertEqual([p.name for p in self.tmp.iterdir()], [])

    def test_default_target_is_current_dir(self):
        import os
        old = os.getcwd()
        os.chdir(self.tmp)
        try:
            with _capture_main([]) as (rc, output):
                pass
        finally:
            os.chdir(old)
        self.assertEqual(rc, 0)
        entries = sorted(p.name for p in self.tmp.rglob("*"))
        self.assertEqual(len(entries), 16)  # 14 plików + 2 katalogi
        self.assertIn("Rozpakowano 14 finalnych plików", output)


if __name__ == "__main__":
    import unittest
    unittest.main()
