"""Archive creation and stream compression operator module for Jarvis.

Provides safe creation of ZIP and TAR archives (.tar, .tar.gz, .tar.bz2, .tar.xz)
and bounded stream compression/decompression (gzip, bz2, lzma) using EXCLUSIVELY
the Python standard library.
"""

from __future__ import annotations

import base64
import bz2
import fnmatch
import gzip
import io
import lzma
import os
import posixpath
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Any

# Security boundaries
HOME = Path.home().resolve()
ALLOWED_ROOTS = (HOME, Path("/tmp").resolve(), Path("/mnt").resolve(), Path("/media").resolve())

MAX_SOURCE_FILES = 1000
MAX_UNCOMPRESSED_ARCHIVE_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_STREAM_INPUT_BYTES = 10 * 1024 * 1024          # 10 MB
MAX_UNCOMPRESSED_STREAM_BYTES = 10 * 1024 * 1024   # 10 MB
STREAM_CHUNK_SIZE = 65536                          # 64 KB

SENSITIVE_PARTS = frozenset({
    ".ssh", ".gnupg", ".password-store", ".hermes/.env", ".env",
    ".config/google-chrome", ".config/chromium", ".mozilla", "config.json",
    ".aws", ".docker/config.json", ".kube/config", ".git-credentials",
    ".npmrc", ".pypirc", ".config/gh", ".config/gcloud",
    ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv",
    ".xprofile", ".xsessionrc", ".gitconfig", ".config/autostart",
    ".config/systemd", ".config/environment.d", ".local/share/applications",
})

SENSITIVE_FILENAMES = frozenset({
    ".env", "config.json", "secrets.json", ".git-credentials",
    ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
})

SENSITIVE_EXTENSIONS = frozenset({".pem", ".key", ".pkcs12", ".pfx"})

KNOWN_ARGUMENTS = frozenset({
    "action",
    "source_paths",
    "source_path",
    "sources",
    "destination_path",
    "archive_path",
    "destination",
    "format",
    "compression",
    "compression_level",
    "data",
    "payload",
    "is_base64",
    "return_base64",
    "overwrite",
    "base_dir",
    "include_pattern",
    "exclude_pattern",
})


class ArchiveError(Exception):
    """Base exception for archive operations."""


class SecurityError(ArchiveError):
    """Raised for security boundary violations (confinement, traversal, sensitive files)."""


class DecompressionBombError(ArchiveError):
    """Raised when decompressed stream exceeds maximum safety limits."""


class PayloadSizeError(ArchiveError):
    """Raised when input payload exceeds size limits."""


def _envelope_success(data: Any) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator success envelope."""
    return {"ok": True, "success": True, "data": data, "result": data, "error": None}


def _envelope_error(error: str | Exception) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator error envelope."""
    if isinstance(error, Exception):
        msg = f"{type(error).__name__}: {error}"
    else:
        msg = str(error)
    return {"ok": False, "success": False, "data": None, "result": None, "error": msg}


def _is_inside_allowed_roots(p: Path) -> bool:
    """Check if resolved path resides within ALLOWED_ROOTS."""
    try:
        resolved = Path(os.path.realpath(str(p)))
        for root in ALLOWED_ROOTS:
            try:
                root_res = Path(os.path.realpath(str(root)))
                if resolved == root_res or resolved.is_relative_to(root_res):
                    return True
            except (OSError, ValueError):
                continue
        return False
    except (OSError, ValueError, RuntimeError):
        return False


def _is_sensitive_path(path: Path) -> bool:
    """Check whether a path targets sensitive credentials, keys, or configurations."""
    name = path.name.lower()
    if name in SENSITIVE_FILENAMES:
        return True
    if name.startswith(".env") and (len(name) == 4 or name[4] in ".-_"):
        return True
    if path.suffix.lower() in SENSITIVE_EXTENSIONS and any(k in name for k in ("id_", "key", "cert", "secret")):
        return True
    parts = [part.lower() for part in path.parts]
    for sensitive in SENSITIVE_PARTS:
        s_parts = [p.lower() for p in sensitive.split("/")]
        s_len = len(s_parts)
        for i in range(len(parts) - s_len + 1):
            if parts[i:i + s_len] == s_parts:
                return True
    return False


def _resolve_and_confine(raw: Any, *, must_exist: bool = False, base: Path = HOME) -> Path:
    """Resolve path, reject directory traversal attempts, and verify confinement to ALLOWED_ROOTS."""
    if not isinstance(raw, (str, Path)) or not str(raw).strip():
        raise ValueError("A file path must be non-empty text.")

    raw_str = str(raw).strip()
    if "\x00" in raw_str:
        raise SecurityError(f"Null bytes not permitted in path: '{raw_str}'")

    raw_path_obj = Path(raw_str)
    if any(part == ".." for part in raw_path_obj.parts):
        # Check if parent traversal is present
        # In strict check, verify if raw string explicitly uses ..
        p_expanded = raw_path_obj.expanduser()
        if not p_expanded.is_absolute():
            p_expanded = base / p_expanded
        resolved = Path(os.path.realpath(str(p_expanded)))
        if not _is_inside_allowed_roots(resolved):
            raise SecurityError(f"Parent directory traversal ('..') is rejected: '{raw_str}'")
    else:
        p_expanded = raw_path_obj.expanduser()
        if not p_expanded.is_absolute():
            p_expanded = base / p_expanded
        resolved = Path(os.path.realpath(str(p_expanded)))

    if not _is_inside_allowed_roots(resolved):
        raise SecurityError(
            f"Path '{raw_str}' resolves to '{resolved}', which is outside "
            "allowed roots (HOME, /tmp, /mnt, /media)."
        )

    if must_exist and not resolved.exists() and not resolved.is_symlink():
        raise FileNotFoundError(f"Source path does not exist: '{resolved}'")

    return resolved


def _sanitize_arcname(arcname: str) -> str:
    """Normalize archive member name and prevent Zip Slip / Tar Slip traversal."""
    if "\x00" in arcname:
        raise SecurityError(f"Null byte detected in archive member name: {arcname!r}")

    # Cross-platform normalization: replace backslashes with forward slashes
    clean_name = str(arcname).replace("\\", "/")

    # Check for traversal tokens in raw path components
    raw_tokens = [part for part in clean_name.split("/") if part]
    if any(token == ".." for token in raw_tokens):
        raise SecurityError(f"Path traversal detected in archive member name: '{arcname}'")

    # Normalize path and strip leading slashes and Windows drive letters
    norm = posixpath.normpath(clean_name).lstrip("/")
    if len(norm) >= 2 and norm[1] == ":" and norm[0].isalpha():
        norm = norm[2:].lstrip("/")

    if not norm or norm == ".":
        norm = "archive_entry"

    # Verify no traversal tokens remain after normalization
    norm_parts = [part for part in norm.split("/") if part]
    if any(part == ".." for part in norm_parts) or norm == ".." or norm.startswith("../") or "/../" in norm:
        raise SecurityError(f"Path traversal detected in archive member name: '{arcname}'")

    return norm


def _create_temp_destination(dest: Path) -> Path:
    """Create sibling temporary file with permissions 0o600."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = dest.with_name(f".{dest.name}-{os.getpid()}-{time.time_ns()}.tmp")
    fd = os.open(str(temp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    os.close(fd)
    return temp


def _commit_temp_file(temp: Path, dest: Path) -> None:
    """Atomically replace destination with temporary file and enforce 0o600 mode."""
    try:
        temp.chmod(0o600)
    except OSError:
        pass
    os.replace(str(temp), str(dest))
    try:
        dest.chmod(0o600)
    except OSError:
        pass


def _collect_files(
    sources: list[Path],
    base_dir: Path | None,
    include_patterns: list[str] | None,
    exclude_patterns: list[str] | None,
) -> tuple[list[tuple[Path, str]], list[str], int, int]:
    """Collect (file_path, arcname) pairs, sensitive exclusions, byte counts, and directory count."""
    items_to_add: list[tuple[Path, str]] = []
    excluded_sensitive: list[str] = []
    total_bytes = 0
    dir_count = 0

    for src in sources:
        if _is_sensitive_path(src):
            raise SecurityError(f"Direct access to sensitive path '{src}' is blocked.")

        if src.is_file():
            arcname = _sanitize_arcname(src.name if base_dir is None else str(src.relative_to(base_dir)))
            size = src.stat().st_size
            total_bytes += size
            items_to_add.append((src, arcname))
        elif src.is_dir():
            dir_count += 1
            src_base = base_dir if base_dir is not None else src.parent
            for root, dirs, files in os.walk(str(src)):
                root_path = Path(root)
                try:
                    rel_root = root_path.relative_to(src_base)
                except ValueError:
                    rel_root = root_path

                # Check directory sensitivity
                if _is_sensitive_path(root_path):
                    excluded_sensitive.append(str(rel_root))
                    dirs.clear()
                    continue

                for d in list(dirs):
                    d_path = root_path / d
                    try:
                        rel_d = d_path.relative_to(src_base)
                    except ValueError:
                        rel_d = d_path
                    if _is_sensitive_path(d_path):
                        excluded_sensitive.append(str(rel_d))
                        dirs.remove(d)
                        continue
                    if d_path.is_symlink():
                        try:
                            resolved_d = d_path.resolve()
                        except (OSError, RuntimeError):
                            resolved_d = None
                        if resolved_d is None or not _is_inside_allowed_roots(resolved_d) or _is_sensitive_path(resolved_d):
                            excluded_sensitive.append(str(rel_d))
                            dirs.remove(d)
                            continue

                for f in sorted(files):
                    f_path = root_path / f
                    try:
                        rel_path = f_path.relative_to(src_base)
                    except ValueError:
                        rel_path = f_path
                    rel_str = str(rel_path)

                    if _is_sensitive_path(f_path):
                        excluded_sensitive.append(rel_str)
                        continue

                    # Defend against symlink exfiltration: inspect symlink targets
                    if f_path.is_symlink():
                        try:
                            resolved_target = f_path.resolve()
                        except (OSError, RuntimeError):
                            excluded_sensitive.append(rel_str)
                            continue

                        if not _is_inside_allowed_roots(resolved_target) or _is_sensitive_path(resolved_target):
                            excluded_sensitive.append(rel_str)
                            continue

                    if include_patterns and not any(fnmatch.fnmatch(f, p) or fnmatch.fnmatch(rel_str, p) for p in include_patterns):
                        continue
                    if exclude_patterns and any(fnmatch.fnmatch(f, p) or fnmatch.fnmatch(rel_str, p) for p in exclude_patterns):
                        continue

                    if len(items_to_add) >= MAX_SOURCE_FILES:
                        raise ArchiveError(f"Exceeded maximum archive entry limit ({MAX_SOURCE_FILES} files).")

                    try:
                        size = f_path.stat().st_size
                    except OSError:
                        size = 0
                    total_bytes += size
                    if total_bytes > MAX_UNCOMPRESSED_ARCHIVE_BYTES:
                        raise ArchiveError(
                            f"Exceeded maximum uncompressed archive size limit ({MAX_UNCOMPRESSED_ARCHIVE_BYTES} bytes)."
                        )

                    arcname = _sanitize_arcname(rel_str)
                    items_to_add.append((f_path, arcname))

    return items_to_add, sorted(set(excluded_sensitive)), total_bytes, dir_count


def _handle_create_zip(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute create_zip action."""
    raw_sources = arguments.get("source_paths") or arguments.get("sources") or arguments.get("source_path")
    if not raw_sources:
        raise ValueError("Parameter 'source_paths' is required for create_zip.")
    if isinstance(raw_sources, (str, Path)):
        source_list = [raw_sources]
    elif isinstance(raw_sources, list):
        source_list = raw_sources
    else:
        raise ValueError("Parameter 'source_paths' must be a list of strings or single string.")

    raw_dest = arguments.get("destination_path") or arguments.get("archive_path") or arguments.get("destination")
    if not raw_dest:
        raise ValueError("Parameter 'destination_path' is required for create_zip.")

    overwrite = bool(arguments.get("overwrite", False))
    level = arguments.get("compression_level", 6)
    if not isinstance(level, int) or not (0 <= level <= 9):
        raise ValueError(f"compression_level must be an integer between 0 and 9, got: {level}")

    raw_base_dir = arguments.get("base_dir")
    base_dir = _resolve_and_confine(raw_base_dir, must_exist=True) if raw_base_dir else None

    # Resolve sources
    sources: list[Path] = []
    for s in source_list:
        sources.append(_resolve_and_confine(s, must_exist=True))

    # Resolve destination
    dest_path = _resolve_and_confine(raw_dest, must_exist=False)
    if _is_sensitive_path(dest_path):
        raise SecurityError(f"Direct access to sensitive path '{dest_path}' is blocked.")

    if dest_path.exists() and not overwrite:
        raise FileExistsError(f"Destination file '{dest_path}' already exists (overwrite=False).")

    include_patterns = arguments.get("include_pattern")
    exclude_patterns = arguments.get("exclude_pattern")

    items_to_add, excluded_sensitive, total_uncompressed, dir_count = _collect_files(
        sources, base_dir, include_patterns, exclude_patterns
    )

    compression_mode = zipfile.ZIP_STORED if level == 0 else zipfile.ZIP_DEFLATED
    temp_dest = _create_temp_destination(dest_path)

    try:
        kwargs: dict[str, Any] = {"compression": compression_mode}
        if compression_mode == zipfile.ZIP_DEFLATED:
            kwargs["compresslevel"] = level

        with zipfile.ZipFile(str(temp_dest), mode="w", **kwargs) as zf:
            for f_path, arcname in items_to_add:
                zf.write(str(f_path), arcname=arcname)

        _commit_temp_file(temp_dest, dest_path)
    except Exception:
        if temp_dest.exists():
            try:
                temp_dest.unlink()
            except OSError:
                pass
        raise

    archive_size = dest_path.stat().st_size
    ratio = round(archive_size / max(1, total_uncompressed), 4)

    return _envelope_success({
        "action": "create_zip",
        "archive_path": str(dest_path),
        "format": "zip",
        "compression_level": level,
        "file_count": len(items_to_add),
        "directory_count": dir_count,
        "total_uncompressed_bytes": total_uncompressed,
        "archive_size_bytes": archive_size,
        "compression_ratio": ratio,
        "files": [arcname for _, arcname in items_to_add],
        "excluded_sensitive_files": excluded_sensitive,
    })


def _handle_create_tar(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute create_tar action."""
    raw_sources = arguments.get("source_paths") or arguments.get("sources") or arguments.get("source_path")
    if not raw_sources:
        raise ValueError("Parameter 'source_paths' is required for create_tar.")
    if isinstance(raw_sources, (str, Path)):
        source_list = [raw_sources]
    elif isinstance(raw_sources, list):
        source_list = raw_sources
    else:
        raise ValueError("Parameter 'source_paths' must be a list of strings or single string.")

    raw_dest = arguments.get("destination_path") or arguments.get("archive_path") or arguments.get("destination")
    if not raw_dest:
        raise ValueError("Parameter 'destination_path' is required for create_tar.")

    overwrite = bool(arguments.get("overwrite", False))
    level = arguments.get("compression_level", 6)
    if not isinstance(level, int) or not (0 <= level <= 9):
        raise ValueError(f"compression_level must be an integer between 0 and 9, got: {level}")

    fmt = str(arguments.get("format") or arguments.get("compression") or "tar.gz").lower()
    valid_tar_formats = {
        "tar": "w",
        "tar.gz": "w:gz",
        "tgz": "w:gz",
        "tar.bz2": "w:bz2",
        "tbz2": "w:bz2",
        "tar.xz": "w:xz",
        "txz": "w:xz",
    }
    if fmt not in valid_tar_formats:
        raise ValueError(f"Unsupported TAR format '{fmt}'. Supported: tar, tar.gz, tar.bz2, tar.xz")

    tar_mode = valid_tar_formats[fmt]

    raw_base_dir = arguments.get("base_dir")
    base_dir = _resolve_and_confine(raw_base_dir, must_exist=True) if raw_base_dir else None

    # Resolve sources
    sources: list[Path] = []
    for s in source_list:
        sources.append(_resolve_and_confine(s, must_exist=True))

    # Resolve destination
    dest_path = _resolve_and_confine(raw_dest, must_exist=False)
    if _is_sensitive_path(dest_path):
        raise SecurityError(f"Direct access to sensitive path '{dest_path}' is blocked.")

    if dest_path.exists() and not overwrite:
        raise FileExistsError(f"Destination file '{dest_path}' already exists (overwrite=False).")

    include_patterns = arguments.get("include_pattern")
    exclude_patterns = arguments.get("exclude_pattern")

    items_to_add, excluded_sensitive, total_uncompressed, dir_count = _collect_files(
        sources, base_dir, include_patterns, exclude_patterns
    )

    temp_dest = _create_temp_destination(dest_path)

    def _tar_filter(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo | None:
        norm = _sanitize_arcname(tarinfo.name)
        tarinfo.name = norm
        tarinfo.uid = 0
        tarinfo.gid = 0
        tarinfo.uname = ""
        tarinfo.gname = ""
        if tarinfo.isdir():
            tarinfo.mode = 0o755
        elif tarinfo.isreg():
            tarinfo.mode = 0o644
        elif tarinfo.issym():
            try:
                link_p = Path(tarinfo.linkname)
                if link_p.is_absolute():
                    res_link = Path(os.path.realpath(str(link_p)))
                elif base_dir is not None:
                    res_link = Path(os.path.realpath(str(base_dir / link_p)))
                else:
                    res_link = Path(os.path.realpath(str(link_p)))
                if not _is_inside_allowed_roots(res_link) or _is_sensitive_path(res_link):
                    return None
            except Exception:
                return None
        else:
            return None
        return tarinfo

    try:
        kwargs: dict[str, Any] = {"mode": tar_mode}
        if tar_mode == "w:gz":
            kwargs["compresslevel"] = level

        with tarfile.open(name=str(temp_dest), **kwargs) as tf:
            for f_path, arcname in items_to_add:
                tf.add(str(f_path), arcname=arcname, recursive=False, filter=_tar_filter)

        _commit_temp_file(temp_dest, dest_path)
    except Exception:
        if temp_dest.exists():
            try:
                temp_dest.unlink()
            except OSError:
                pass
        raise

    archive_size = dest_path.stat().st_size
    ratio = round(archive_size / max(1, total_uncompressed), 4)

    return _envelope_success({
        "action": "create_tar",
        "archive_path": str(dest_path),
        "format": fmt,
        "compression_level": level,
        "file_count": len(items_to_add),
        "directory_count": dir_count,
        "total_uncompressed_bytes": total_uncompressed,
        "archive_size_bytes": archive_size,
        "compression_ratio": ratio,
        "files": [arcname for _, arcname in items_to_add],
        "excluded_sensitive_files": excluded_sensitive,
    })


def _handle_compress_stream(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute compress_stream action."""
    raw_data = arguments.get("data") if arguments.get("data") is not None else arguments.get("payload")
    raw_src = arguments.get("source_path")

    if raw_data is None and not raw_src:
        raise ValueError("Either 'data' payload or 'source_path' must be provided for compress_stream.")

    if raw_data is not None:
        if not isinstance(raw_data, str):
            raise ValueError("Parameter 'data' must be a string.")
        is_b64 = bool(arguments.get("is_base64", False))
        if is_b64:
            try:
                uncompressed_bytes = base64.b64decode(raw_data)
            except Exception as e:
                raise ValueError(f"Failed to decode base64 input data: {e}") from e
        else:
            uncompressed_bytes = raw_data.encode("utf-8")
    else:
        src_path = _resolve_and_confine(raw_src, must_exist=True)
        if _is_sensitive_path(src_path):
            raise SecurityError(f"Direct access to sensitive path '{src_path}' is blocked.")
        if src_path.stat().st_size > MAX_STREAM_INPUT_BYTES:
            raise PayloadSizeError(f"Source file exceeds maximum stream size limit ({MAX_STREAM_INPUT_BYTES} bytes).")
        uncompressed_bytes = src_path.read_bytes()

    if len(uncompressed_bytes) > MAX_STREAM_INPUT_BYTES:
        raise PayloadSizeError(f"Payload size ({len(uncompressed_bytes)} bytes) exceeds maximum limit of 10 MB.")

    fmt = str(arguments.get("format") or arguments.get("compression") or "gzip").lower()
    level = arguments.get("compression_level", 9)
    if not isinstance(level, int) or not (0 <= level <= 9):
        raise ValueError(f"compression_level must be between 0 and 9, got: {level}")

    if fmt in ("gzip", "gz"):
        compressed_bytes = gzip.compress(uncompressed_bytes, compresslevel=level)
        canonical_fmt = "gzip"
    elif fmt in ("bz2", "bzip2"):
        compressed_bytes = bz2.compress(uncompressed_bytes, compresslevel=max(1, level))
        canonical_fmt = "bz2"
    elif fmt in ("lzma", "xz"):
        preset = min(9, max(0, level))
        compressed_bytes = lzma.compress(uncompressed_bytes, preset=preset)
        canonical_fmt = "lzma"
    else:
        raise ValueError(f"Unsupported compression algorithm '{fmt}'. Supported: gzip, bz2, lzma")

    raw_dest = arguments.get("destination_path") or arguments.get("destination") or arguments.get("archive_path")
    ratio = round(len(compressed_bytes) / max(1, len(uncompressed_bytes)), 4)

    if raw_dest:
        overwrite = bool(arguments.get("overwrite", False))
        dest_path = _resolve_and_confine(raw_dest, must_exist=False)
        if _is_sensitive_path(dest_path):
            raise SecurityError(f"Direct access to sensitive path '{dest_path}' is blocked.")
        if dest_path.exists() and not overwrite:
            raise FileExistsError(f"Destination file '{dest_path}' already exists (overwrite=False).")

        temp_dest = _create_temp_destination(dest_path)
        try:
            temp_dest.write_bytes(compressed_bytes)
            _commit_temp_file(temp_dest, dest_path)
        except Exception:
            if temp_dest.exists():
                try:
                    temp_dest.unlink()
                except OSError:
                    pass
            raise

        return _envelope_success({
            "action": "compress_stream",
            "format": canonical_fmt,
            "uncompressed_bytes": len(uncompressed_bytes),
            "compressed_bytes": len(compressed_bytes),
            "compression_ratio": ratio,
            "destination_path": str(dest_path),
            "data": None,
            "is_base64": False,
        })
    else:
        return_b64 = bool(arguments.get("return_base64", True))
        if return_b64:
            out_str = base64.b64encode(compressed_bytes).decode("ascii")
            out_is_b64 = True
        else:
            out_str = compressed_bytes.decode("latin1")
            out_is_b64 = False

        return _envelope_success({
            "action": "compress_stream",
            "format": canonical_fmt,
            "uncompressed_bytes": len(uncompressed_bytes),
            "compressed_bytes": len(compressed_bytes),
            "compression_ratio": ratio,
            "destination_path": None,
            "data": out_str,
            "is_base64": out_is_b64,
        })


def _handle_decompress_stream(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute decompress_stream action with 10MB decompression bomb safeguard."""
    raw_data = arguments.get("data") if arguments.get("data") is not None else arguments.get("payload")
    raw_src = arguments.get("source_path")

    if raw_data is None and not raw_src:
        raise ValueError("Either 'data' payload or 'source_path' must be provided for decompress_stream.")

    if raw_data is not None:
        if not isinstance(raw_data, str):
            raise ValueError("Parameter 'data' must be a string.")
        # Auto-detect whether base64
        try:
            compressed_bytes = base64.b64decode(raw_data)
        except Exception:
            compressed_bytes = raw_data.encode("latin1")
    else:
        src_path = _resolve_and_confine(raw_src, must_exist=True)
        if _is_sensitive_path(src_path):
            raise SecurityError(f"Direct access to sensitive path '{src_path}' is blocked.")
        compressed_bytes = src_path.read_bytes()

    fmt = str(arguments.get("format") or arguments.get("compression") or "").lower()
    if not fmt:
        # Detect from magic bytes
        if compressed_bytes.startswith(b"\x1f\x8b"):
            fmt = "gzip"
        elif compressed_bytes.startswith(b"BZh"):
            fmt = "bz2"
        elif compressed_bytes.startswith(b"\xfd7zXZ\x00"):
            fmt = "lzma"
        else:
            fmt = "gzip"

    if fmt in ("gzip", "gz"):
        canonical_fmt = "gzip"
    elif fmt in ("bz2", "bzip2"):
        canonical_fmt = "bz2"
    elif fmt in ("lzma", "xz"):
        canonical_fmt = "lzma"
    else:
        raise ValueError(f"Unsupported decompression algorithm '{fmt}'. Supported: gzip, bz2, lzma")

    # Bounded streaming decompression enforcing 10MB limit
    decompressed_chunks: list[bytes] = []
    total_decompressed = 0

    try:
        if canonical_fmt == "gzip":
            try:
                bio = io.BytesIO(compressed_bytes)
                with gzip.GzipFile(fileobj=bio, mode="rb") as gz:
                    while True:
                        chunk = gz.read(STREAM_CHUNK_SIZE)
                        if not chunk:
                            break
                        total_decompressed += len(chunk)
                        if total_decompressed > MAX_UNCOMPRESSED_STREAM_BYTES:
                            raise DecompressionBombError(
                                f"Decompressed size exceeds maximum safety limit of "
                                f"{MAX_UNCOMPRESSED_STREAM_BYTES} bytes (10 MB)"
                            )
                        decompressed_chunks.append(chunk)
            except (gzip.BadGzipFile, OSError, EOFError) as e:
                if isinstance(e, DecompressionBombError):
                    raise
                raise ArchiveError(f"Invalid or corrupted gzip compressed stream: {e}") from e

        elif canonical_fmt == "bz2":
            try:
                decompressor = bz2.BZ2Decompressor()
                bio = io.BytesIO(compressed_bytes)
                while True:
                    in_chunk = bio.read(STREAM_CHUNK_SIZE)
                    if not in_chunk:
                        break
                    chunk = decompressor.decompress(in_chunk, max_length=STREAM_CHUNK_SIZE)
                    while chunk:
                        total_decompressed += len(chunk)
                        if total_decompressed > MAX_UNCOMPRESSED_STREAM_BYTES:
                            raise DecompressionBombError(
                                f"Decompressed size exceeds maximum safety limit of "
                                f"{MAX_UNCOMPRESSED_STREAM_BYTES} bytes (10 MB)"
                            )
                        decompressed_chunks.append(chunk)
                        if decompressor.eof:
                            break
                        chunk = decompressor.decompress(b"", max_length=STREAM_CHUNK_SIZE)
                    if decompressor.eof:
                        break
                if not decompressor.eof:
                    raise ValueError("Compressed data stream is incomplete or truncated.")
            except OSError as e:
                if isinstance(e, DecompressionBombError):
                    raise
                raise ArchiveError(f"Invalid or corrupted bz2 compressed stream: {e}") from e

        elif canonical_fmt == "lzma":
            try:
                decompressor = lzma.LZMADecompressor()
                bio = io.BytesIO(compressed_bytes)
                while True:
                    in_chunk = bio.read(STREAM_CHUNK_SIZE)
                    if not in_chunk:
                        break
                    chunk = decompressor.decompress(in_chunk, max_length=STREAM_CHUNK_SIZE)
                    while chunk:
                        total_decompressed += len(chunk)
                        if total_decompressed > MAX_UNCOMPRESSED_STREAM_BYTES:
                            raise DecompressionBombError(
                                f"Decompressed size exceeds maximum safety limit of "
                                f"{MAX_UNCOMPRESSED_STREAM_BYTES} bytes (10 MB)"
                            )
                        decompressed_chunks.append(chunk)
                        if decompressor.eof:
                            break
                        chunk = decompressor.decompress(b"", max_length=STREAM_CHUNK_SIZE)
                    if decompressor.eof:
                        break
                if not decompressor.eof:
                    raise ValueError("Compressed data stream is incomplete or truncated.")
            except lzma.LZMAError as e:
                raise ArchiveError(f"Invalid or corrupted lzma compressed stream: {e}") from e

    except DecompressionBombError:
        raise

    decompressed_bytes = b"".join(decompressed_chunks)

    raw_dest = arguments.get("destination_path") or arguments.get("destination") or arguments.get("archive_path")
    if raw_dest:
        overwrite = bool(arguments.get("overwrite", False))
        dest_path = _resolve_and_confine(raw_dest, must_exist=False)
        if _is_sensitive_path(dest_path):
            raise SecurityError(f"Direct access to sensitive path '{dest_path}' is blocked.")
        if dest_path.exists() and not overwrite:
            raise FileExistsError(f"Destination file '{dest_path}' already exists (overwrite=False).")

        temp_dest = _create_temp_destination(dest_path)
        try:
            temp_dest.write_bytes(decompressed_bytes)
            _commit_temp_file(temp_dest, dest_path)
        except Exception:
            if temp_dest.exists():
                try:
                    temp_dest.unlink()
                except OSError:
                    pass
            raise

        return _envelope_success({
            "action": "decompress_stream",
            "format": canonical_fmt,
            "compressed_bytes": len(compressed_bytes),
            "uncompressed_bytes": len(decompressed_bytes),
            "destination_path": str(dest_path),
            "data": None,
            "is_text": False,
            "is_base64": False,
        })
    else:
        return_b64 = bool(arguments.get("return_base64", False))
        is_text = False
        out_is_b64 = False
        out_str = None

        if not return_b64:
            try:
                out_str = decompressed_bytes.decode("utf-8")
                is_text = True
                out_is_b64 = False
            except UnicodeDecodeError:
                out_str = base64.b64encode(decompressed_bytes).decode("ascii")
                is_text = False
                out_is_b64 = True
        else:
            out_str = base64.b64encode(decompressed_bytes).decode("ascii")
            is_text = False
            out_is_b64 = True

        return _envelope_success({
            "action": "decompress_stream",
            "format": canonical_fmt,
            "compressed_bytes": len(compressed_bytes),
            "uncompressed_bytes": len(decompressed_bytes),
            "destination_path": None,
            "data": out_str,
            "is_text": is_text,
            "is_base64": out_is_b64,
        })


def archive_builder(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute archive builder action adhering to Jarvis operator standards."""
    if not isinstance(arguments, dict):
        return _envelope_error(ValueError("Arguments must be a dictionary."))

    for key in arguments:
        if key not in KNOWN_ARGUMENTS:
            return _envelope_error(ValueError(f"Unknown argument '{key}' or schema violation"))

    action = arguments.get("action")
    if not action or not isinstance(action, str):
        return _envelope_error(ValueError("Missing required parameter 'action'"))

    try:
        if action == "create_zip":
            return _handle_create_zip(arguments)
        elif action == "create_tar":
            return _handle_create_tar(arguments)
        elif action == "compress_stream":
            return _handle_compress_stream(arguments)
        elif action == "decompress_stream":
            return _handle_decompress_stream(arguments)
        else:
            return _envelope_error(ValueError(f"Invalid or unsupported action '{action}'"))
    except Exception as exc:
        return _envelope_error(exc)


TOOL = {
    "name": "archive_builder",
    "description": (
        "Create compressed archives (ZIP, TAR, tar.gz, tar.bz2, tar.xz) or perform bounded stream "
        "compression and decompression (gzip, bz2, lzma) with canonical path confinement to "
        "ALLOWED_ROOTS, sensitive target exclusion, path traversal protection, atomic 0o600 "
        "file creation, and strict decompression bomb safeguards (10 MB limit)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["create_zip", "create_tar", "compress_stream", "decompress_stream"],
                "description": "Archive creation or stream compression/decompression action to execute.",
            },
            "source_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of source file or directory paths to include in the archive (for create_zip, create_tar).",
            },
            "source_path": {
                "type": "string",
                "description": "Convenience alias for a single source file or directory path.",
            },
            "sources": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Alias for source_paths.",
            },
            "destination_path": {
                "type": "string",
                "description": "Target archive or output file destination path. Must reside within ALLOWED_ROOTS.",
            },
            "archive_path": {
                "type": "string",
                "description": "Alias for destination_path.",
            },
            "destination": {
                "type": "string",
                "description": "Alias for destination_path.",
            },
            "format": {
                "type": "string",
                "enum": ["zip", "tar", "tar.gz", "tar.bz2", "tar.xz", "gzip", "bz2", "lzma"],
                "description": "Archive or stream compression format. Defaults to 'zip' for create_zip, 'tar.gz' for create_tar, and 'gzip' for stream actions.",
            },
            "compression": {
                "type": "string",
                "description": "Alias for format or compression algorithm.",
            },
            "compression_level": {
                "type": "integer",
                "minimum": 0,
                "maximum": 9,
                "description": "Compression level from 0 (none/store) to 9 (maximum).",
            },
            "data": {
                "type": "string",
                "description": "Payload string for stream operations (UTF-8 text or base64-encoded string).",
            },
            "payload": {
                "type": "string",
                "description": "Alias for data.",
            },
            "is_base64": {
                "type": "boolean",
                "description": "Whether the input 'data' payload is base64 encoded.",
            },
            "return_base64": {
                "type": "boolean",
                "description": "Whether stream output should be returned as base64 encoded text.",
            },
            "overwrite": {
                "type": "boolean",
                "description": "Allow overwriting destination file if it already exists (default: false).",
            },
            "base_dir": {
                "type": "string",
                "description": "Optional base directory for computing relative paths of members inside the archive.",
            },
            "include_pattern": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of glob patterns to include (e.g. ['*.py', '*.txt']).",
            },
            "exclude_pattern": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of glob patterns to exclude (e.g. ['*.tmp', '*.log']).",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": archive_builder,
    "approval": True,
}
