"""ERROR-path coverage tests for operator_modules/archive_ops.py.

Third module of the sys.settrace audit: 23 raise sites, only 4 ever
executed by the existing suite. archive_ops is the extraction-security
module - Zip Slip traversal, link and device refusal, protected
destinations, entry and byte budgets - so its untreated error branches
are exactly the ones that must never rust. This suite drives them with
hand-crafted zip/tar archives (zipfile.ZipInfo with S_IFCHR mode bits,
TarInfo with SYMTYPE/CHRTYPE) and direct helper probes.

Two raise lines are verified dead under stdlib reader semantics and stay
untested, documented here: the ``extractfile``-is-None branch (the member
walk already refuses every non-regular member, so a reachable None cannot
happen) and the "expanded past the byte budget" check (a size-lying zip is
cut off by zipfile's CRC/declared-size enforcement before the count can
run past the declared total, and extractfile is bounded by the header
size - while the declared total is already capped by the earlier check).
"""
import stat
import tarfile
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import operator_modules.archive_ops as ops


class ArchiveErrorCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def call(self, action="list", archive=None, destination=None):
        args = {"action": action, "archive": archive}
        if destination is not None:
            args["destination"] = destination
        return ops.archive_ops(args)

    def zip_with(self, name, entries):
        path = self.tmp / name
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
            for member, payload in entries:
                zf.writestr(member, payload)
        return path

    def tar_with(self, name, infos):
        path = self.tmp / name
        with tarfile.open(path, "w") as tf:
            for info in infos:
                tf.addfile(info)
        return path


class DispatcherGuardTests(ArchiveErrorCase):
    def test_blank_archive_path_is_rejected(self):
        result = self.call(archive="   ")
        self.assertFalse(result["ok"])
        self.assertIn("A path must be non-empty text.", result["error"])

    def test_missing_archive_file(self):
        result = self.call(archive=str(self.tmp / "nope.zip"))
        self.assertFalse(result["ok"])
        self.assertIn("That archive does not exist.", result["error"])

    def test_plain_file_is_not_an_archive(self):
        plain = self.tmp / "notes.txt"
        plain.write_text("hello", encoding="utf-8")
        result = self.call(archive=str(plain))
        self.assertFalse(result["ok"])
        self.assertIn("Only zip and tar archives are supported.",
                      result["error"])

    def test_archive_outside_readable_roots(self):
        result = self.call(archive="/etc/hostname")
        self.assertFalse(result["ok"])
        self.assertIn("outside the readable roots", result["error"])

    def test_protected_archive_name(self):
        secret = self.tmp / ".git-credentials"
        secret.write_text("not really credentials", encoding="utf-8")
        result = self.call(archive=str(secret))
        self.assertFalse(result["ok"])
        self.assertIn("That archive path is protected.", result["error"])

    def test_unsupported_action_reports_envelope(self):
        ok_zip = self.zip_with("ok.zip", [("a.txt", "x")])
        result = ops.archive_ops({"action": "teleport",
                                  "archive": str(ok_zip)})
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"],
                         "Unsupported action; use list or extract.")

    def test_corrupt_zip_reports_badzipfile(self):
        corrupt = self.tmp / "corrupt.zip"
        corrupt.write_bytes(b"PK\x03\x04garbage-not-an-archive")
        result = self.call(archive=str(corrupt))
        self.assertFalse(result["ok"])
        self.assertIn("BadZipFile", result["error"])


class SpecialMemberTests(ArchiveErrorCase):
    def test_zip_special_entry_is_refused(self):
        path = self.tmp / "dev.zip"
        with zipfile.ZipFile(path, "w") as zf:
            info = zipfile.ZipInfo("dev-node")
            info.external_attr = (stat.S_IFCHR | 0o644) << 16
            zf.writestr(info, "x")
        result = self.call(archive=str(path))
        self.assertFalse(result["ok"])
        self.assertIn("Refusing a special entry: dev-node", result["error"])

    def test_tar_symlink_entry_is_refused(self):
        info = tarfile.TarInfo("evil-link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        archive = self.tar_with("link.tar", [info])
        result = self.call(archive=str(archive))
        self.assertFalse(result["ok"])
        self.assertIn("Refusing a link entry: evil-link", result["error"])

    def test_tar_char_device_entry_is_refused(self):
        info = tarfile.TarInfo("dev-zero")
        info.type = tarfile.CHRTYPE
        archive = self.tar_with("chr.tar", [info])
        result = self.call(archive=str(archive))
        self.assertFalse(result["ok"])
        self.assertIn("Refusing a special entry: dev-zero", result["error"])


class TargetNameTests(ArchiveErrorCase):
    def test_absolute_entry_name_is_refused(self):
        with self.assertRaises(ops.ArchiveError) as ctx:
            ops._target_for(self.tmp / "dest", "/etc/passwd")
        self.assertIn("absolute or empty", str(ctx.exception))
        with self.assertRaises(ops.ArchiveError):
            ops._target_for(self.tmp / "dest", "file\x00.txt")

    def test_symlinked_destination_escape_is_refused(self):
        # The destination directory itself is a symlink: resolve() jumps
        # outside, so the guard must refuse what looks like a local name.
        outside = self.tmp / "outside"
        outside.mkdir()
        linked = self.tmp / "linked-dest"
        linked.symlink_to(outside)
        with self.assertRaises(ops.ArchiveError) as ctx:
            ops._target_for(linked, "payload.txt")
        self.assertIn("outside the destination", str(ctx.exception))


class ExtractGuardTests(ArchiveErrorCase):
    """Direct extract() probes; _inside_home is neutralised only after
    the other home guard paths are covered through the real dispatcher,
    so the in-process destination checks run against a tmp tree."""

    def test_protected_destination_via_dispatcher(self):
        archive = self.zip_with("p.zip", [("a.txt", "x")])
        result = self.call(action="extract", archive=str(archive),
                           destination=str(Path.home() / ".ssh"))
        self.assertFalse(result["ok"])
        self.assertIn("That destination is protected.", result["error"])

    def _extract(self, archive, destination):
        return ops.extract(archive, destination)

    def test_destination_file_not_directory(self):
        archive = self.zip_with("p.zip", [("a.txt", "x")])
        blocker = self.tmp / "blocker.txt"
        blocker.write_text("a file", encoding="utf-8")
        with patch.object(ops, "_inside_home", lambda p: True):
            with self.assertRaises(ops.ArchiveError) as ctx:
                self._extract(archive, blocker)
        self.assertIn("exists and is not a directory", str(ctx.exception))

    def test_entry_count_ceiling(self):
        archive = self.zip_with("many.zip",
                                [("a.txt", "x"), ("b.txt", "y")])
        dest = self.tmp / "dest"
        with patch.object(ops, "_inside_home", lambda p: True), \
                patch.object(ops, "MAX_ENTRIES", 1):
            with self.assertRaises(ops.ArchiveError) as ctx:
                self._extract(archive, dest)
        self.assertIn("more than 1 entries", str(ctx.exception))

    def test_declared_byte_budget(self):
        archive = self.zip_with("heavy.zip",
                                [("a.txt", "z" * 150),
                                 ("b.txt", "z" * 150)])
        dest = self.tmp / "dest"
        with patch.object(ops, "_inside_home", lambda p: True), \
                patch.object(ops, "MAX_TOTAL_BYTES", 200):
            with self.assertRaises(ops.ArchiveError) as ctx:
                self._extract(archive, dest)
        self.assertIn("more uncompressed data than allowed",
                      str(ctx.exception))
        # The refusal happens before the first write: dest holds no
        # member files, only the empty directory itself.
        self.assertEqual(list(dest.iterdir()), [])

    def test_entry_landing_on_protected_path(self):
        archive = self.zip_with("sneaky.zip",
                                [(".ssh/id_rsa", "key data")])
        dest = self.tmp / "dest"
        with patch.object(ops, "_inside_home", lambda p: True):
            with self.assertRaises(ops.ArchiveError) as ctx:
                self._extract(archive, dest)
        self.assertIn("lands on a protected path", str(ctx.exception))
        self.assertEqual(list(dest.iterdir()), [])

    def test_refusing_to_overwrite_existing_file(self):
        archive = self.zip_with("dup.zip", [("f.txt", "new")])
        dest = self.tmp / "dest"
        dest.mkdir()
        (dest / "f.txt").write_text("old", encoding="utf-8")
        with patch.object(ops, "_inside_home", lambda p: True):
            with self.assertRaises(ops.ArchiveError) as ctx:
                self._extract(archive, dest)
        self.assertIn("Refusing to overwrite", str(ctx.exception))
        self.assertEqual((dest / "f.txt").read_text(encoding="utf-8"),
                         "old")

    def test_member_copy_respects_entry_ceiling(self):
        target = self.tmp / "partial.bin"
        with patch.object(ops, "MAX_ENTRY_BYTES", 65536):
            with self.assertRaises(ops.ArchiveError) as ctx:
                ops._copy_member(BytesIO(b"z" * 400000), target)
        self.assertIn("Entry grew past", str(ctx.exception))
        # Observed boundary: the refused entry leaves its partial file
        # behind (the dispatcher-level rollback removes completed files,
        # not the half-written current one).
        self.assertTrue(target.exists())


if __name__ == "__main__":
    unittest.main()
