"""ERROR-path coverage tests for operator_modules/op_archive_builder.py.

Born from a sys.settrace audit of the CF iteration: the module has 55
raise sites but the existing 205 tests only ever execute 12 of them.
This suite drives the untouched, reachable error branches through the
public ``archive_builder`` dispatcher: parameter validation, sensitive
path blocking, stream size limits, decompression bombs, corrupted and
truncated streams, entry limits, and the atomic temp-file cleanup on
write failures. It also pins the gzip EOFError fix: a truncated gzip
stream must surface as the module's own ArchiveError, not leak a raw
EOFError (bz2/lzma branches already had clean handling).

Three raise lines are verified dead on purpose and stay untested:
the ``isinstance(e, DecompressionBombError)`` re-raises inside the
gzip/bz2 ``except`` clauses - the bomb is not an OSError subclass, so
those handlers can never see it; the outer targeted handler (766)
re-raises it instead. And the post-normalization traversal check in
_sanitize_arcname is a duplicate guard: posixpath.normpath can only
produce ".." from inputs that already contain a ".." token, and the
raw-token pre-check rejects exactly those.
"""
import base64
import gzip
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import operator_modules.op_archive_builder as op_ab


class ErrorPathCase(unittest.TestCase):
    """Shared dispatch helper with per-test tmpdir isolation."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def call(self, **kwargs):
        result = op_ab.archive_builder(kwargs)
        self.assertIsInstance(result, dict)
        self.assertIn("ok", result)
        self.assertIn("error", result)
        return result

    def ok_call(self, **kwargs):
        result = self.call(**kwargs)
        self.assertTrue(result["ok"], msg=str(result["error"]))
        return result

    def mkfile(self, name, content="data", where=None):
        target = (where or self.tmp) / name
        target.write_text(content, encoding="utf-8")
        return target

    def b64(self, raw: bytes) -> str:
        return base64.b64encode(raw).decode("ascii")


class SanitizeAndConfineGuards(ErrorPathCase):
    """Path hygiene helpers behind create_* handlers."""

    def test_empty_source_path_is_rejected(self):
        result = self.call(action="create_tar", source_paths=[""],
                           destination_path=str(self.tmp / "a.tar"))
        self.assertFalse(result["ok"])
        self.assertIn("non-empty text", result["error"])

    def test_null_byte_in_source_path_is_rejected(self):
        result = self.call(action="create_tar",
                           source_paths=[str(self.tmp) + "/a\x00b"],
                           destination_path=str(self.tmp / "a.tar"))
        self.assertFalse(result["ok"])
        self.assertIn("Null bytes not permitted", result["error"])

    def test_arcname_null_byte_is_rejected(self):
        with self.assertRaises(op_ab.SecurityError):
            op_ab._sanitize_arcname("dir\x00file.txt")

    def test_arcname_traversal_is_rejected(self):
        with self.assertRaises(op_ab.SecurityError):
            op_ab._sanitize_arcname("../etc/passwd")


class CreateZipErrorPaths(ErrorPathCase):
    def test_missing_sources(self):
        result = self.call(action="create_zip",
                          destination_path=str(self.tmp / "a.zip"))
        self.assertFalse(result["ok"])
        self.assertIn("source_paths' is required for create_zip",
                      result["error"])

    def test_wrong_sources_type(self):
        result = self.call(action="create_zip", source_paths={"a": 1},
                           destination_path=str(self.tmp / "a.zip"))
        self.assertFalse(result["ok"])
        self.assertIn("list of strings or single string", result["error"])

    def test_missing_destination(self):
        src = self.mkfile("one.txt")
        result = self.call(action="create_zip", source_paths=[str(src)])
        self.assertFalse(result["ok"])
        self.assertIn("destination_path' is required for create_zip",
                      result["error"])

    def test_invalid_compression_level(self):
        src = self.mkfile("one.txt")
        result = self.call(action="create_zip", source_paths=[str(src)],
                           destination_path=str(self.tmp / "a.zip"),
                           compression_level=11)
        self.assertFalse(result["ok"])
        self.assertIn("compression_level must be an integer between 0 and 9",
                      result["error"])

    def test_sensitive_destination_blocked(self):
        src = self.mkfile("one.txt")
        result = self.call(action="create_zip", source_paths=[str(src)],
                           destination_path=str(self.tmp / "config.json"))
        self.assertFalse(result["ok"])
        self.assertIn("SecurityError", result["error"])
        self.assertIn("sensitive path", result["error"])

    def test_entry_limit_enforced(self):
        bulk = self.tmp / "many"
        bulk.mkdir()
        for i in range(1001):
            (bulk / f"f{i:04d}").write_text("", encoding="utf-8")
        result = self.call(action="create_zip", source_paths=[str(bulk)],
                           destination_path=str(self.tmp / "a.zip"))
        self.assertFalse(result["ok"])
        self.assertIn("maximum archive entry limit", result["error"])

    def test_uncompressed_size_limit_enforced(self):
        bulk = self.tmp / "heavy"
        bulk.mkdir()
        (bulk / "a.bin").write_text("aaaa", encoding="utf-8")
        (bulk / "b.bin").write_text("bbbb", encoding="utf-8")
        with patch.object(op_ab, "MAX_UNCOMPRESSED_ARCHIVE_BYTES", 4):
            result = self.call(action="create_zip",
                               source_paths=[str(bulk)],
                               destination_path=str(self.tmp / "a.zip"))
        self.assertFalse(result["ok"])
        self.assertIn("maximum uncompressed archive size limit",
                      result["error"])

    def test_commit_failure_cleans_temp_file(self):
        src = self.mkfile("one.txt")
        dest = self.tmp / "out.zip"

        def boom(temp, dest_path):
            raise OSError("simulated commit failure")

        with patch.object(op_ab, "_commit_temp_file", boom):
            result = self.call(action="create_zip",
                              source_paths=[str(src)],
                              destination_path=str(dest))
        self.assertFalse(result["ok"])
        self.assertIn("simulated commit failure", result["error"])
        self.assertEqual(list(self.tmp.iterdir()), [src])


class CreateTarErrorPaths(ErrorPathCase):
    def _src(self):
        return self.mkfile("note.txt", "hello tar")

    def test_missing_sources(self):
        result = self.call(action="create_tar",
                           destination_path=str(self.tmp / "a.tar"))
        self.assertFalse(result["ok"])
        self.assertIn("source_paths' is required for create_tar",
                      result["error"])

    def test_wrong_sources_type(self):
        result = self.call(action="create_tar", source_paths=42,
                           destination_path=str(self.tmp / "a.tar"))
        self.assertFalse(result["ok"])
        self.assertIn("list of strings or single string", result["error"])

    def test_missing_destination(self):
        src = self._src()
        result = self.call(action="create_tar", source_paths=[str(src)])
        self.assertFalse(result["ok"])
        self.assertIn("destination_path' is required for create_tar",
                      result["error"])

    def test_invalid_compression_level(self):
        src = self._src()
        result = self.call(action="create_tar", source_paths=[str(src)],
                           destination_path=str(self.tmp / "a.tar"),
                           compression_level="high")
        self.assertFalse(result["ok"])
        self.assertIn("compression_level must be an integer between 0 and 9",
                      result["error"])

    def test_unsupported_format(self):
        src = self._src()
        result = self.call(action="create_tar", source_paths=[str(src)],
                           destination_path=str(self.tmp / "a.tar"),
                           format="tar.7z")
        self.assertFalse(result["ok"])
        self.assertIn("Unsupported TAR format", result["error"])

    def test_sensitive_destination_blocked(self):
        src = self._src()
        result = self.call(action="create_tar", source_paths=[str(src)],
                           destination_path=str(self.tmp / "config.json"))
        self.assertFalse(result["ok"])
        self.assertIn("sensitive path", result["error"])

    def test_existing_destination_requires_overwrite(self):
        src = self._src()
        dest = self.mkfile("existing.tar", "stub")
        result = self.call(action="create_tar", source_paths=[str(src)],
                           destination_path=str(dest))
        self.assertFalse(result["ok"])
        self.assertIn("already exists (overwrite=False)",
                      result["error"])
        # The stub content must not be clobbered by a partial archive.
        self.assertEqual(dest.read_text(encoding="utf-8"), "stub")

    def test_commit_failure_cleans_temp_file(self):
        src = self._src()
        dest = self.tmp / "out.tar"

        def boom(temp, dest_path):
            raise OSError("simulated commit failure")

        with patch.object(op_ab, "_commit_temp_file", boom):
            result = self.call(action="create_tar",
                               source_paths=[str(src)],
                               destination_path=str(dest))
        self.assertFalse(result["ok"])
        self.assertIn("simulated commit failure", result["error"])
        self.assertEqual(list(self.tmp.iterdir()), [src])


class CompressStreamErrorPaths(ErrorPathCase):
    def test_neither_data_nor_source(self):
        result = self.call(action="compress_stream")
        self.assertFalse(result["ok"])
        self.assertIn("data' payload or 'source_path'",
                      result["error"])

    def test_non_string_data(self):
        result = self.call(action="compress_stream", data=12345)
        self.assertFalse(result["ok"])
        self.assertIn("Parameter 'data' must be a string.",
                      result["error"])

    def test_invalid_base64_payload(self):
        result = self.call(action="compress_stream",
                           data="not base64!!!", is_base64=True)
        self.assertFalse(result["ok"])
        self.assertIn("Failed to decode base64 input data",
                      result["error"])

    def test_sensitive_source_file_blocked(self):
        secret = self.mkfile("config.json", '{"k": "v"}')
        result = self.call(action="compress_stream",
                           source_path=str(secret))
        self.assertFalse(result["ok"])
        self.assertIn("sensitive path", result["error"])

    def test_oversize_source_file_rejected(self):
        big = self.mkfile("big.bin")
        big.write_bytes(b"x" * 64)
        with patch.object(op_ab, "MAX_STREAM_INPUT_BYTES", 32):
            result = self.call(action="compress_stream",
                               source_path=str(big))
        self.assertFalse(result["ok"])
        self.assertIn("Source file exceeds maximum stream size limit",
                      result["error"])

    def test_oversize_payload_rejected(self):
        with patch.object(op_ab, "MAX_STREAM_INPUT_BYTES", 8):
            result = self.call(action="compress_stream",
                               data="this string is longer than eight")
        self.assertFalse(result["ok"])
        self.assertIn("exceeds maximum limit", result["error"])

    def test_invalid_compression_level(self):
        result = self.call(action="compress_stream", data="abc",
                           compression_level=42)
        self.assertFalse(result["ok"])
        self.assertIn("compression_level must be between 0 and 9",
                      result["error"])

    def test_unsupported_algorithm(self):
        result = self.call(action="compress_stream", data="abc",
                           format="zstd")
        self.assertFalse(result["ok"])
        self.assertIn("Unsupported compression algorithm 'zstd'",
                      result["error"])

    def test_sensitive_destination_blocked(self):
        result = self.call(action="compress_stream", data="abc",
                           destination_path=str(self.tmp / ".env"))
        self.assertFalse(result["ok"])
        self.assertIn("sensitive path", result["error"])

    def test_existing_destination_requires_overwrite(self):
        dest = self.mkfile("out.gz", "stub")
        result = self.call(action="compress_stream", data="abc",
                           destination_path=str(dest))
        self.assertFalse(result["ok"])
        self.assertIn("already exists (overwrite=False)",
                      result["error"])

    def test_commit_failure_cleans_temp_file(self):
        dest = self.tmp / "out.gz"

        def boom(temp, dest_path):
            raise OSError("simulated commit failure")

        with patch.object(op_ab, "_commit_temp_file", boom):
            result = self.call(action="compress_stream", data="abc",
                               destination_path=str(dest))
        self.assertFalse(result["ok"])
        self.assertIn("simulated commit failure", result["error"])
        self.assertEqual(list(self.tmp.iterdir()), [])


class DecompressStreamErrorPaths(ErrorPathCase):
    def _b64(self, raw: bytes) -> str:
        return base64.b64encode(raw).decode("ascii")

    def test_neither_data_nor_source(self):
        result = self.call(action="decompress_stream")
        self.assertFalse(result["ok"])
        self.assertIn("data' payload or 'source_path'",
                      result["error"])

    def test_non_string_data(self):
        result = self.call(action="decompress_stream", payload=b"bytes")
        self.assertFalse(result["ok"])
        self.assertIn("Parameter 'data' must be a string.",
                      result["error"])

    def test_sensitive_source_file_blocked(self):
        secret = self.mkfile("config.json", "gz data")
        result = self.call(action="decompress_stream",
                           source_path=str(secret))
        self.assertFalse(result["ok"])
        self.assertIn("sensitive path", result["error"])

    def test_unsupported_algorithm(self):
        payload = self._b64(gzip.compress(b"abc"))
        result = self.call(action="decompress_stream", data=payload,
                           format="zstd")
        self.assertFalse(result["ok"])
        self.assertIn("Unsupported decompression algorithm 'zstd'",
                      result["error"])

    def test_corrupt_gzip_reports_archive_error_not_raw_eof(self):
        # Pre-fix this leaked a raw EOFError (truncated gzip streams raise
        # EOFError, which the handler did not catch).
        truncated = gzip.compress(b"payload " * 100)[:-8]
        result = self.call(action="decompress_stream",
                           data=self._b64(truncated), format="gzip")
        self.assertFalse(result["ok"])
        self.assertIn("ArchiveError", result["error"])
        self.assertIn("Invalid or corrupted gzip compressed stream",
                      result["error"])
        self.assertNotIn("EOFError", result["error"])

    def test_garbage_gzip_reports_archive_error(self):
        result = self.call(action="decompress_stream",
                           data=self._b64(b"totally not gzip"),
                           format="gzip")
        self.assertFalse(result["ok"])
        self.assertIn("Invalid or corrupted gzip compressed stream",
                      result["error"])

    def test_gzip_decompression_bomb_blocked(self):
        bomb = gzip.compress(b"A" * 65536)
        with patch.object(op_ab, "MAX_UNCOMPRESSED_STREAM_BYTES", 4096):
            result = self.call(action="decompress_stream",
                               data=self._b64(bomb), format="gzip")
        self.assertFalse(result["ok"])
        self.assertIn("DecompressionBombError", result["error"])
        self.assertIn("maximum safety limit", result["error"])

    def test_corrupt_bz2_reports_archive_error(self):
        result = self.call(action="decompress_stream",
                           data=self._b64(b"BZh9garbagegarbagegarbage"),
                           format="bz2")
        self.assertFalse(result["ok"])
        self.assertIn("Invalid or corrupted bz2 compressed stream",
                      result["error"])

    def test_truncated_bz2_reports_incomplete_stream(self):
        import bz2
        truncated = bz2.compress(b"payload " * 100)[:-10]
        result = self.call(action="decompress_stream",
                           data=self._b64(truncated), format="bz2")
        self.assertFalse(result["ok"])
        self.assertIn("incomplete or truncated", result["error"])

    def test_bz2_decompression_bomb_blocked(self):
        import bz2
        bomb = bz2.compress(b"B" * 65536)
        with patch.object(op_ab, "MAX_UNCOMPRESSED_STREAM_BYTES", 4096):
            result = self.call(action="decompress_stream",
                               data=self._b64(bomb), format="bz2")
        self.assertFalse(result["ok"])
        self.assertIn("DecompressionBombError", result["error"])

    def test_corrupt_lzma_reports_archive_error(self):
        corrupted = b"\xfd7zXZ\x00garbagegarbage"
        result = self.call(action="decompress_stream",
                           data=self._b64(corrupted), format="lzma")
        self.assertFalse(result["ok"])
        self.assertIn("Invalid or corrupted lzma compressed stream",
                      result["error"])

    def test_truncated_lzma_reports_incomplete_stream(self):
        import lzma
        truncated = lzma.compress(b"payload " * 100)[:-4]
        result = self.call(action="decompress_stream",
                           data=self._b64(truncated), format="lzma")
        self.assertFalse(result["ok"])
        self.assertIn("incomplete or truncated", result["error"])

    def test_lzma_decompression_bomb_blocked(self):
        import lzma
        bomb = lzma.compress(b"C" * 65536)
        with patch.object(op_ab, "MAX_UNCOMPRESSED_STREAM_BYTES", 4096):
            result = self.call(action="decompress_stream",
                               data=self._b64(bomb), format="lzma")
        self.assertFalse(result["ok"])
        self.assertIn("DecompressionBombError", result["error"])

    def test_sensitive_destination_blocked(self):
        payload = self._b64(gzip.compress(b"abc"))
        result = self.call(action="decompress_stream", data=payload,
                           destination_path=str(self.tmp / ".env"))
        self.assertFalse(result["ok"])
        self.assertIn("sensitive path", result["error"])

    def test_existing_destination_requires_overwrite(self):
        payload = self._b64(gzip.compress(b"abc"))
        dest = self.mkfile("out.bin", "stub")
        result = self.call(action="decompress_stream", data=payload,
                           destination_path=str(dest))
        self.assertFalse(result["ok"])
        self.assertIn("already exists (overwrite=False)",
                      result["error"])

    def test_commit_failure_cleans_temp_file(self):
        import gzip as gzip_mod
        payload = self._b64(gzip_mod.compress(b"abc"))
        dest = self.tmp / "out.bin"

        def boom(temp, dest_path):
            raise OSError("simulated commit failure")

        with patch.object(op_ab, "_commit_temp_file", boom):
            result = self.call(action="decompress_stream", data=payload,
                               destination_path=str(dest))
        self.assertFalse(result["ok"])
        self.assertIn("simulated commit failure", result["error"])
        self.assertEqual(list(self.tmp.iterdir()), [])


class FixedBehaviorSmoke(ErrorPathCase):
    def test_valid_stream_roundtrip_still_works_after_fix(self):
        payload = self.b64(gzip.compress(b"round trip payload"))
        result = self.ok_call(action="decompress_stream", data=payload,
                              format="gzip", return_base64=True)
        out = base64.b64decode(result["data"]["data"])
        self.assertEqual(out, b"round trip payload")


if __name__ == "__main__":
    unittest.main()
