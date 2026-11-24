"""List or unpack an archive without letting the Operator weaponise it.

The generated fixes proposed a plain ``safe_extract_archive`` library; a
library is unreachable from the Operator, so this is a real registered tool
with the same guards plus the ones a tool needs: the destination must sit
inside the home workspace, outside the sensitive set, and every entry is
written by hand so no member can escape through ``..``, an absolute name, a
symlink, a hardlink, a device node, an oversized file or a decompression bomb.

``list`` is read-only. ``extract`` writes files and therefore asks for
approval before it runs.
"""
from __future__ import annotations

import os
import stat
import tarfile
import zipfile
from pathlib import Path

MAX_ENTRIES = 2000
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_ENTRY_BYTES = 128 * 1024 * 1024
CHUNK = 1024 * 256


class ArchiveError(Exception):
    """The archive was refused or could not be unpacked safely."""


def _resolve(raw, base=None) -> Path:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 4096:
        raise ArchiveError("A path must be non-empty text.")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = Path(base or Path.home()) / candidate
    return candidate.resolve()


def _inside_home(target: Path) -> bool:
    home = Path.home().resolve()
    return target == home or home in target.parents


def _allowed_source(target: Path) -> bool:
    import operator_tools
    return operator_tools._inside(target, operator_tools.ALLOWED_ROOTS)


def _sensitive(target: Path) -> bool:
    import operator_tools  # imported late: keeps module discovery cheap
    return operator_tools.is_sensitive_target(target)


def _kind(path: Path) -> str:
    name = path.name.casefold()
    if name.endswith((".zip", ".whl", ".jar", ".apk")):
        return "zip"
    if name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
        return "tar"
    if zipfile.is_zipfile(path):
        return "zip"
    if tarfile.is_tarfile(path):
        return "tar"
    raise ArchiveError("Only zip and tar archives are supported.")


def _zip_members(handle: zipfile.ZipFile) -> list[dict]:
    rows = []
    for info in handle.infolist():
        mode = (info.external_attr >> 16) & 0xFFFF
        kind_bits = mode & 0o170000          # type bits; 0 means "permissions only"
        if kind_bits == stat.S_IFLNK:
            raise ArchiveError(f"Refusing a symlink entry: {info.filename}")
        if info.is_dir():
            rows.append({"name": info.filename, "dir": True, "size": 0})
            continue
        if kind_bits not in (0, stat.S_IFREG):
            raise ArchiveError(f"Refusing a special entry: {info.filename}")
        rows.append({"name": info.filename, "dir": False, "size": info.file_size})
    return rows


def _tar_members(handle: tarfile.TarFile) -> list[dict]:
    rows = []
    for member in handle.getmembers():
        if member.issym() or member.islnk():
            raise ArchiveError(f"Refusing a link entry: {member.name}")
        if member.isdir():
            rows.append({"name": member.name, "dir": True, "size": 0})
            continue
        if not member.isfile():
            raise ArchiveError(f"Refusing a special entry: {member.name}")
        rows.append({"name": member.name, "dir": False, "size": member.size})
    return rows


def _target_for(destination: Path, name: str) -> Path:
    raw = str(name or "")
    if not raw or raw.startswith(("/", "\\")) or "\x00" in raw:
        raise ArchiveError(f"Refusing an absolute or empty entry name: {raw!r}")
    parts = Path(raw.replace("\\", "/")).parts
    if any(part in ("..", "") for part in parts):
        raise ArchiveError(f"Refusing a traversal entry: {raw}")
    target = (destination / Path(*parts)).resolve()
    if destination not in target.parents and target != destination:
        raise ArchiveError(f"Refusing an entry outside the destination: {raw}")
    return target


def open_archive(path: Path):
    kind = _kind(path)
    return (zipfile.ZipFile(path) if kind == "zip" else tarfile.open(path)), kind


def describe(archive: Path) -> dict:
    stat_info = archive.stat()
    handle, kind = open_archive(archive)
    try:
        members = _zip_members(handle) if kind == "zip" else _tar_members(handle)
    finally:
        handle.close()
    files = [row for row in members if not row["dir"]]
    return {
        "ok": True,
        "format": kind,
        "bytes": stat_info.st_size,
        "entries": len(members),
        "files": len(files),
        "uncompressed_bytes": sum(int(row["size"] or 0) for row in files),
        "largest": max([int(row["size"] or 0) for row in files], default=0),
        "sample": [row["name"] for row in files[:20]],
    }


def _copy_member(source, target: Path) -> int:
    written = 0
    with target.open("xb") as out:
        while True:
            chunk = source.read(CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_ENTRY_BYTES:
                raise ArchiveError(f"Entry grew past {MAX_ENTRY_BYTES} bytes: {target.name}")
            out.write(chunk)
    return written


def extract(archive: Path, destination: Path) -> dict:
    if not _inside_home(destination):
        raise ArchiveError("The destination must be inside your home directory.")
    if _sensitive(destination):
        raise ArchiveError("That destination is protected.")
    if destination.exists() and not destination.is_dir():
        raise ArchiveError("The destination exists and is not a directory.")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)

    handle, kind = open_archive(archive)
    created: list[str] = []
    total = 0
    try:
        members = _zip_members(handle) if kind == "zip" else _tar_members(handle)
        if len(members) > MAX_ENTRIES:
            raise ArchiveError(f"The archive has more than {MAX_ENTRIES} entries.")
        declared = sum(int(row["size"] or 0) for row in members)
        if declared > MAX_TOTAL_BYTES:
            raise ArchiveError("The archive declares more uncompressed data than allowed.")
        for row in members:
            target = _target_for(destination, row["name"])
            if _sensitive(target):
                raise ArchiveError(f"Refusing an entry that lands on a protected path: "
                                   f"{row['name']}")
            if row["dir"]:
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if target.exists():
                raise ArchiveError(f"Refusing to overwrite: {target}")
            if kind == "zip":
                with handle.open(row["name"]) as source:
                    total += _copy_member(source, target)
            else:
                source = handle.extractfile(row["name"])
                if source is None:
                    raise ArchiveError(f"Could not read entry: {row['name']}")
                with source:
                    total += _copy_member(source, target)
            os.chmod(target, 0o600)
            created.append(str(target))
            if total > MAX_TOTAL_BYTES:
                raise ArchiveError("The archive expanded past the byte budget.")
    except Exception:
        for path in reversed(created):
            try:
                os.unlink(path)
            except OSError:
                pass
        raise
    finally:
        handle.close()
    return {"ok": True, "extracted": len(created), "bytes": total,
            "destination": str(destination), "files": created[:50]}


def archive_ops(arguments, context=None):
    del context
    arguments = arguments or {}
    action = str(arguments.get("action") or "list").strip().lower()
    try:
        archive = _resolve(arguments.get("archive"))
        if not archive.is_file():
            raise ArchiveError("That archive does not exist.")
        if not _allowed_source(archive):
            raise ArchiveError("The archive is outside the readable roots (home, /tmp, "
                               "/mnt, /media).")
        if _sensitive(archive):
            raise ArchiveError("That archive path is protected.")
        if action == "list":
            return describe(archive)
        if action == "extract":
            destination = _resolve(arguments.get("destination"))
            return extract(archive, destination)
        return {"ok": False, "error": "Unsupported action; use list or extract."}
    except ArchiveError as error:
        return {"ok": False, "error": str(error)}
    except (OSError, zipfile.BadZipFile, tarfile.TarError) as error:
        return {"ok": False, "error": f"{type(error).__name__}: {error}"}


TOOL = {
    "name": "archive_ops",
    "description": ("List or safely unpack a zip/tar archive into a directory inside "
                    "the home workspace. Refuses traversal, links, devices, overwrites "
                    "and bombs."),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["list", "extract"]},
            "archive": {"type": "string", "description": "Path to the .zip/.tar file."},
            "destination": {"type": "string",
                            "description": "Target directory for action=extract."},
        },
        "required": ["action", "archive"],
        "additionalProperties": False,
    },
    "handler": archive_ops,
    "approval": True,
}
