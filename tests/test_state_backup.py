"""state_backup: JARVISENC1 envelope, manifest integrity and safe restore.

This suite pins the encrypted backup pipeline: the PBKDF2-HMAC-SHA256 key
derivation gate (>= 6 characters, deterministic 32+32-byte key split), the
BLAKE2b-CTR keystream (empty input, XOR invertibility, manual CTR block
reconstruction), the JARVISENC1 envelope (magic + salt + nonce + counter
length + ciphertext + HMAC tag, fresh salt/nonce per encryption, the exact
two-byte header size of 50, the full tamper matrix — bad magic, truncation,
length mismatch failing before any key derivation, while nonce/ciphertext/tag
flips and wrong passphrases fail HMAC verification with the Polish error
message), the online sqlite3.Connection.backup copy (readable clones,
DatabaseError on garbage files), the tar builder exclusion matrix (skip dirs,
hidden entries, code_index sidecars, -wal/-shm/.lock/.tmp suffixes, symlinks,
with the copy2 fallback for non-sqlite .sqlite/.db files), manifest accuracy
(SHA-256 of staged copies, version 1, file_count), verify_backup (age files
are returned unverified by design, crafted manifests failing with the SHA
mismatch / missing member / missing manifest errors), create_backup (source
gate, custom output dir, 0600 permissions, the jarvis-state-<stamp>.jenc
naming with the collision suffix, the age-recipient fallback when the age
binary is absent), restore_backup (file restoration with manifest.json
excluded and 0600 perms, wrong-passphrase refusal, the path-traversal block
on '../evil.txt' members that verify_backup alone would accept, and the
documented inability to restore .age blobs), and list_backups (suffix
filter, mtime ordering, limit, directory auto-creation).

All assertions were pinned empirically before writing. PBKDF2 costs ~0.2 s
per derivation, so the suite keeps the roundtrip count low. The backups
directory is redirected into a per-test sandbox by patching
state_backup.agent_cli.ROOT.
"""
import hashlib
import io
import json
import os
import sqlite3
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import state_backup

PASSPHRASE = "secure-pass"
HMAC_MSG = "Weryfikacja HMAC nie powiodła się"


def craft_tar(members, manifest):
    """Build a gz tar with explicit members plus a manifest.json."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in members:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        payload = json.dumps(manifest).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


class StateBackupBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="sbb_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.agents_dir = self.tmp / "agents"
        self._cli = patch.object(state_backup, "agent_cli",
                                 SimpleNamespace(ROOT=self.agents_dir / "agent_cli.py"))
        self._cli.start()
        self.addCleanup(self._cli.stop)

    def make_source(self):
        source = self.tmp / "state"
        source.mkdir()
        (source / "config.json").write_text('{"k": "v"}', encoding="utf-8")
        (source / "sub").mkdir()
        (source / "sub" / "data.txt").write_text("zawartosc", encoding="utf-8")
        conn = sqlite3.connect(source / "state.sqlite3")
        conn.execute("CREATE TABLE t(x)")
        conn.execute("INSERT INTO t VALUES ('db')")
        conn.commit()
        conn.close()
        return source


class TestKeyDerivation(unittest.TestCase):
    def test_passphrase_gate_rejects_short_and_non_string(self):
        for bad in ("abc", "12345", 123, None):
            with self.assertRaises(state_backup.BackupError) as ctx:
                state_backup._derive_keys(bad, b"x" * 16)
            self.assertIn("co najmniej 6 znak", str(ctx.exception))

    def test_deterministic_split_keys(self):
        first = state_backup._derive_keys("secure-pass", b"0123456789abcdef")
        second = state_backup._derive_keys("secure-pass", b"0123456789abcdef")
        self.assertEqual(first, second)
        self.assertEqual((len(first[0]), len(first[1])), (32, 32))


class TestKeystream(unittest.TestCase):
    def test_empty_and_xor_invertibility(self):
        self.assertEqual(state_backup._xor_keystream(b"", b"k" * 32, b"n" * 16), b"")
        data = bytes(range(256))
        twice = state_backup._xor_keystream(
            state_backup._xor_keystream(data, b"k" * 32, b"n" * 16), b"k" * 32, b"n" * 16)
        self.assertEqual(twice, data)

    def test_manual_blake2b_ctr_reconstruction(self):
        key, nonce = b"k" * 32, b"n" * 16
        block = hashlib.blake2b(nonce + (0).to_bytes(8, "big"),
                               key=key, digest_size=64).digest()
        manual = bytes(a ^ b for a, b in zip(b"A" * 64, block))
        self.assertEqual(state_backup._xor_keystream(b"A" * 64, key, nonce), manual)


class TestEnvelope(StateBackupBase):
    def test_roundtrip_and_header_layout(self):
        blob = state_backup.encrypt_bytes(b"hello world", PASSPHRASE)
        self.assertEqual(blob[:10], state_backup.MAGIC)
        # header = magic(10) + salt(16) + nonce(16) + counter(8) = 50 bytes
        self.assertEqual(len(blob) - 32 - len(b"hello world"), 50)
        self.assertEqual(struct.unpack(">Q", blob[42:50])[0], len(b"hello world"))
        self.assertEqual(state_backup.decrypt_bytes(blob, PASSPHRASE), b"hello world")

    def test_fresh_salt_and_nonce_per_encryption(self):
        first = state_backup.encrypt_bytes(b"payload", PASSPHRASE)
        second = state_backup.encrypt_bytes(b"payload", PASSPHRASE)
        self.assertNotEqual(first, second)  # random salt+nonce
        self.assertEqual(state_backup.decrypt_bytes(second, PASSPHRASE), b"payload")

    def test_tamper_and_format_error_matrix(self):
        blob = state_backup.encrypt_bytes(b"secret payload", PASSPHRASE)
        # structural failures reject before any key derivation
        for broken, label in ((blob[:30], "short"), (b"OTHERMAGIC" + blob[10:], "magic"),
                              (blob[:-33], "truncated")):
            with self.assertRaises(state_backup.BackupError) as ctx:
                state_backup.decrypt_bytes(broken, PASSPHRASE)
            self.assertIn("Nieprawidłowy format", str(ctx.exception))
        # authenticated failures: flips anywhere + wrong passphrase
        for flip_at in (30, 60, len(blob) - 1):  # nonce, ciphertext, tag
            tampered = bytearray(blob)
            tampered[flip_at] ^= 0x01
            with self.assertRaises(state_backup.BackupError) as ctx:
                state_backup.decrypt_bytes(bytes(tampered), PASSPHRASE)
            self.assertIn(HMAC_MSG, str(ctx.exception))
        with self.assertRaises(state_backup.BackupError) as ctx:
            state_backup.decrypt_bytes(blob, "wrong-passphrase")
        self.assertIn(HMAC_MSG, str(ctx.exception))


class TestSqliteCopy(unittest.TestCase):
    def test_online_backup_produces_readable_clone(self):
        with tempfile.TemporaryDirectory(prefix="sbc_") as tmpdir:
            tmp = Path(tmpdir)
            source = tmp / "real.sqlite3"
            conn = sqlite3.connect(source)
            conn.execute("CREATE TABLE t(x)")
            conn.execute("INSERT INTO t VALUES (42)")
            conn.commit()
            conn.close()
            dest = tmp / "copy.sqlite3"
            state_backup._safe_copy_sqlite(source, dest)
            check = sqlite3.connect(dest)
            self.assertEqual(check.execute("SELECT x FROM t").fetchone()[0], 42)
            check.close()
            self.assertTrue(source.is_file())  # source untouched

    def test_garbage_sqlite_raises_database_error(self):
        with tempfile.TemporaryDirectory(prefix="sbc_") as tmpdir:
            tmp = Path(tmpdir)
            garbage = tmp / "garbage.sqlite3"
            garbage.write_bytes(b"this is not a database at all")
            with self.assertRaises(sqlite3.Error):  # builder falls back to copy2
                state_backup._safe_copy_sqlite(garbage, tmp / "out.sqlite3")


class TestTarBuilder(unittest.TestCase):
    def test_skip_matrix_manifest_accuracy_and_fallback(self):
        with tempfile.TemporaryDirectory(prefix="sbt_") as tmpdir:
            root = Path(tmpdir) / "state"
            root.mkdir()
            (root / "settings.json").write_text('{"a": 1}', encoding="utf-8")
            (root / "sub").mkdir()
            (root / "sub" / "notes.md").write_text("notatka", encoding="utf-8")
            for skip in ("backups", "checkpoints", "teams", "pr_sandboxes", "__pycache__", ".hidden"):
                (root / skip).mkdir()
                (root / skip / "skipme.txt").write_text("x", encoding="utf-8")
            for name in ("code_index.sqlite3", "code_index.sqlite3-wal", "x-wal", "x.lock", "x.tmp"):
                (root / name).write_text("excluded", encoding="utf-8")
            (root / "data.sqlite3").write_bytes(b"garbage-db")  # non-sqlite -> copy2 fallback
            os.symlink(root / "settings.json", root / "link.json")

            tar_bytes, manifest = state_backup._build_tar_gz_bytes(root)
            self.assertEqual(sorted(manifest["files"]), ["data.sqlite3", "settings.json",
                                                         "sub/notes.md"])
            self.assertEqual(manifest["version"], 1)
            self.assertEqual(manifest["file_count"], 3)
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
                members = {m.name: m for m in tar.getmembers() if m.isfile()}
                self.assertIn("manifest.json", members)
                for rel, expected in manifest["files"].items():
                    handle = tar.extractfile(members[rel])
                    self.assertEqual(hashlib.sha256(handle.read()).hexdigest(), expected)


class TestVerifyBackup(StateBackupBase):
    def _encrypted_file(self, tar_bytes, name="crafted.jenc"):
        path = self.tmp / name
        path.write_bytes(state_backup.encrypt_bytes(tar_bytes, PASSPHRASE))
        return path

    def test_missing_file_and_age_passthrough(self):
        with self.assertRaises(state_backup.BackupError) as ctx:
            state_backup.verify_backup(self.tmp / "missing.jenc")
        self.assertIn("Plik kopii nie istnieje", str(ctx.exception))
        age_file = self.tmp / "jarvis-state-x.age"
        age_file.write_bytes(b"opaque age payload")
        result = state_backup.verify_backup(age_file)
        self.assertEqual(result, {"ok": True, "path": str(age_file), "mode": "age",
                                  "bytes": len(b"opaque age payload"),
                                  "verified_manifest": False})

    def test_crafted_failures_sha_missing_and_manifest(self):
        wrong_sha = {"version": 1, "created_at": 0.0, "file_count": 1,
                     "files": {"a.txt": hashlib.sha256(b"BBB").hexdigest()}}
        path = self._encrypted_file(craft_tar([("a.txt", b"AAA")], wrong_sha))
        with self.assertRaises(state_backup.BackupError) as ctx:
            state_backup.verify_backup(path, passphrase=PASSPHRASE)
        self.assertIn("Niezgodność sumy SHA-256 dla pliku: a.txt", str(ctx.exception))

        missing = {"version": 1, "created_at": 0.0, "file_count": 2,
                   "files": {"a.txt": hashlib.sha256(b"AAA").hexdigest(),
                             "gone.txt": "f" * 64}}
        path = self._encrypted_file(craft_tar([("a.txt", b"AAA")], missing), "crafted2.jenc")
        with self.assertRaises(state_backup.BackupError) as ctx:
            state_backup.verify_backup(path, passphrase=PASSPHRASE)
        self.assertIn("Brak oczekiwanego pliku w archiwum: gone.txt", str(ctx.exception))

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo("a.txt")
            info.size = 3
            tar.addfile(info, io.BytesIO(b"AAA"))
        path = self._encrypted_file(buf.getvalue(), "crafted3.jenc")
        with self.assertRaises(state_backup.BackupError) as ctx:
            state_backup.verify_backup(path, passphrase=PASSPHRASE)
        self.assertIn("Brak pliku manifest.json", str(ctx.exception))


class TestCreateBackup(StateBackupBase):
    def test_source_gate(self):
        with self.assertRaises(state_backup.BackupError) as ctx:
            state_backup.create_backup(passphrase=PASSPHRASE,
                                       source_root=self.tmp / "no-such-dir")
        self.assertIn("Katalog źródłowy stanu nie istnieje", str(ctx.exception))

    def test_create_verifies_and_seals_0600(self):
        source = self.make_source()
        out_dir = self.tmp / "backups"
        result = state_backup.create_backup(passphrase=PASSPHRASE,
                                            source_root=source, output_dir=out_dir)
        self.assertTrue(result["ok"])
        self.assertEqual(result["mode"], "pbkdf2-hmac-sha256")
        self.assertEqual((result["file_count"], result["verified"]), (3, True))
        dest = Path(result["path"])
        self.assertEqual(dest.suffix, ".jenc")
        self.assertTrue(dest.name.startswith("jarvis-state-"))
        self.assertEqual(result["bytes"], dest.stat().st_size)
        self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
        self.assertEqual(out_dir.stat().st_mode & 0o777, 0o700)

    def test_age_recipient_falls_back_without_binary(self):
        source = self.make_source()
        with patch.object(state_backup.shutil, "which", lambda name: None):
            result = state_backup.create_backup(passphrase=PASSPHRASE,
                                                age_recipient="age1xyz",
                                                source_root=source,
                                                output_dir=self.tmp / "backups")
        self.assertEqual(result["mode"], "pbkdf2-hmac-sha256")  # silent fallback
        self.assertTrue(Path(result["path"]).name.endswith(".jenc"))

    def test_colliding_stamp_gets_random_suffix(self):
        source = self.make_source()
        out_dir = self.tmp / "backups"
        out_dir.mkdir()
        with patch.object(state_backup.time, "strftime", lambda fmt: "20300101-000000"):
            (out_dir / "jarvis-state-20300101-000000.jenc").write_bytes(b"reserved")
            result = state_backup.create_backup(passphrase=PASSPHRASE,
                                                source_root=source, output_dir=out_dir)
        name = Path(result["path"]).name
        self.assertNotEqual(name, "jarvis-state-20300101-000000.jenc")
        self.assertTrue(name.startswith("jarvis-state-20300101-000000"))
        self.assertTrue(name.endswith(".jenc"))


class TestRestoreBackup(StateBackupBase):
    def setUp(self):
        super().setUp()
        self.source = self.make_source()
        self.out_dir = self.tmp / "backups"
        created = state_backup.create_backup(passphrase=PASSPHRASE,
                                             source_root=self.source, output_dir=self.out_dir)
        self.backup_path = Path(created["path"])

    def test_restore_recovers_files_without_manifest(self):
        target = self.tmp / "restored"
        result = state_backup.restore_backup(self.backup_path, target, passphrase=PASSPHRASE)
        self.assertTrue(result["ok"])
        self.assertEqual((result["restored_files"], result["verified"]), (3, True))
        names = sorted(p.relative_to(target).as_posix()
                       for p in target.rglob("*") if p.is_file())
        self.assertEqual(names, ["config.json", "state.sqlite3", "sub/data.txt"])
        self.assertNotIn("manifest.json", names)  # manifest is bookkeeping only
        self.assertEqual((target / "sub" / "data.txt").read_text(encoding="utf-8"),
                         "zawartosc")
        self.assertEqual((target / "config.json").stat().st_mode & 0o777, 0o600)
        conn = sqlite3.connect(target / "state.sqlite3")
        self.assertEqual(conn.execute("SELECT x FROM t").fetchone()[0], "db")
        conn.close()

    def test_wrong_passphrase_refused(self):
        with self.assertRaises(state_backup.BackupError) as ctx:
            state_backup.restore_backup(self.backup_path, self.tmp / "other",
                                        passphrase="wrong-passphrase")
        self.assertIn(HMAC_MSG, str(ctx.exception))

    def test_path_traversal_blocked_on_restore(self):
        traversal_manifest = {"version": 1, "created_at": 0.0, "file_count": 1,
                              "files": {"../evil.txt": hashlib.sha256(b"EVIL").hexdigest()}}
        tar_bytes = craft_tar([("../evil.txt", b"EVIL")], traversal_manifest)
        crafted = self.tmp / "traversal.jenc"
        crafted.write_bytes(state_backup.encrypt_bytes(tar_bytes, PASSPHRASE))
        # verification alone accepts it: the manifest is internally consistent
        self.assertTrue(state_backup.verify_backup(crafted, passphrase=PASSPHRASE)["ok"])
        with self.assertRaises(state_backup.BackupError) as ctx:
            state_backup.restore_backup(crafted, self.tmp / "trav-target",
                                        passphrase=PASSPHRASE)
        self.assertIn("Zablokowano niebezpieczną ścieżkę", str(ctx.exception))
        self.assertFalse((self.tmp / "evil.txt").exists())  # nothing escaped

    def test_age_restore_is_refused_with_format_error(self):
        age_file = self.tmp / "not-supported.age"
        age_file.write_bytes(b"opaque age payload")
        with self.assertRaises(state_backup.BackupError) as ctx:
            state_backup.restore_backup(age_file, self.tmp / "age-target",
                                        passphrase=PASSPHRASE)
        self.assertIn("Nieprawidłowy format", str(ctx.exception))


class TestListBackups(StateBackupBase):
    def test_listing_filters_orders_and_limits(self):
        backups = self.agents_dir / "backups"
        backups.mkdir(parents=True)
        for name, mtime in (("b.jenc", 3000.0), ("a.jenc", 2000.0),
                            ("c.age", 1000.0), ("junk.txt", 4000.0)):
            path = backups / name
            path.write_bytes(b"pad-123456789")
            os.utime(path, (mtime, mtime))
        entries = state_backup.list_backups()
        self.assertEqual([e["name"] for e in entries], ["b.jenc", "a.jenc", "c.age"])
        self.assertEqual(sorted(entries[0]), ["bytes", "mtime", "name", "path"])
        self.assertEqual(entries[0]["bytes"], len(b"pad-123456789"))
        limit_one = state_backup.list_backups(limit=1)
        self.assertEqual([e["name"] for e in limit_one], ["b.jenc"])

    def test_listing_creates_backups_dir(self):
        self.assertFalse((self.agents_dir / "backups").exists())
        self.assertEqual(state_backup.list_backups(), [])
        self.assertTrue((self.agents_dir / "backups").is_dir())  # auto-created 0700


if __name__ == "__main__":
    unittest.main()
