"""Encrypted state backup & restore-verification module for Jarvis.

Snapshots Jarvis's durable state (`selfmod/`, `workflows/`, `time_travel/`,
router/budget/watchdog JSONs, and SQLite databases copied safely via online
`sqlite3.Connection.backup`), seals a SHA-256 `manifest.json` inside a `.tar.gz`,
encrypts via `age` CLI (if `age_recipient` is supplied) or a built-in stdlib
`JARVISENC1` authenticated envelope (PBKDF2-HMAC-SHA256 + BLAKE2b-CTR +
Encrypt-then-MAC HMAC-SHA256), and verifies decrypt + manifest integrity.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

import agent_cli

MAGIC = b"JARVISENC1"
KDF_ITERATIONS = 200_000
SKIP_DIRS = {"backups", "pr_sandboxes", "teams", "checkpoints", "__pycache__"}
SKIP_FILES = {"code_index.sqlite3", "code_index.sqlite3-wal", "code_index.sqlite3-shm"}


class BackupError(Exception):
    """Raised on backup creation, encryption, verification, or restore failure."""


def _backups_dir() -> Path:
    d = agent_cli.ROOT.parent / "backups"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def _derive_keys(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
    if not isinstance(passphrase, str) or len(passphrase) < 6:
        raise BackupError("Hasło kopii zapasowej musi mieć co najmniej 6 znaków.")
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, KDF_ITERATIONS, dklen=64)
    return dk[:32], dk[32:]


def _xor_keystream(data: bytes, enc_key: bytes, nonce: bytes) -> bytes:
    out = bytearray(len(data))
    block_size = 64
    for offset in range(0, len(data), block_size):
        counter = (offset // block_size).to_bytes(8, "big")
        ks = hashlib.blake2b(nonce + counter, key=enc_key, digest_size=block_size).digest()
        chunk = data[offset:offset + block_size]
        if len(chunk) < block_size:
            ks = ks[:len(chunk)]
        xored = (int.from_bytes(chunk, "big") ^ int.from_bytes(ks, "big")).to_bytes(len(chunk), "big")
        out[offset:offset + len(chunk)] = xored
    return bytes(out)


def encrypt_bytes(plaintext: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(16)
    enc_key, mac_key = _derive_keys(passphrase, salt)
    ciphertext = _xor_keystream(plaintext, enc_key, nonce)
    header = MAGIC + salt + nonce + struct.pack(">Q", len(ciphertext))
    tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag


def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    min_len = len(MAGIC) + 16 + 16 + 8 + 32
    if len(blob) < min_len or not blob.startswith(MAGIC):
        raise BackupError("Nieprawidłowy format zaszyfrowanej kopii zapasowej.")
    pos = len(MAGIC)
    salt = blob[pos:pos + 16]
    nonce = blob[pos + 16:pos + 32]
    ct_len = struct.unpack(">Q", blob[pos + 32:pos + 40])[0]
    header_end = pos + 40
    if header_end + ct_len + 32 != len(blob):
        raise BackupError("Uszkodzona kopia zapasowa (niezgodna długość ładunku).")
    header = blob[:header_end]
    ciphertext = blob[header_end:header_end + ct_len]
    tag = blob[header_end + ct_len:]

    enc_key, mac_key = _derive_keys(passphrase, salt)
    expected_tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise BackupError("Weryfikacja HMAC nie powiodła się — błędne hasło lub naruszona integralność.")
    return _xor_keystream(ciphertext, enc_key, nonce)


def _safe_copy_sqlite(src: Path, dst: Path) -> None:
    dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    src_conn = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=5.0)
    try:
        dst_conn = sqlite3.connect(str(dst))
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()


def _build_tar_gz_bytes(source_root: Path) -> tuple[bytes, dict]:
    manifest_files: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="jarvis-bkp-stage-") as stage_tmp:
        stage = Path(stage_tmp) / "payload"
        stage.mkdir(mode=0o700, parents=True, exist_ok=True)

        for path in sorted(source_root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            rel = path.relative_to(source_root)
            if any(part in SKIP_DIRS or part.startswith(".") for part in rel.parts):
                continue
            if path.name in SKIP_FILES or path.name.endswith(("-wal", "-shm", ".lock", ".tmp")):
                continue
            dest = stage / rel
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
                try:
                    _safe_copy_sqlite(path, dest)
                except sqlite3.Error:
                    shutil.copy2(path, dest)
            else:
                shutil.copy2(path, dest)
            digest = hashlib.sha256(dest.read_bytes()).hexdigest()
            manifest_files[str(rel)] = digest

        manifest = {
            "version": 1,
            "created_at": round(time.time(), 3),
            "file_count": len(manifest_files),
            "files": manifest_files,
        }
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for item in sorted(stage.rglob("*")):
                if item.is_file():
                    arcname = str(item.relative_to(stage))
                    tar.add(str(item), arcname=arcname)
        return buf.getvalue(), manifest


def verify_backup(backup_path: str | Path, passphrase: str = "") -> dict:
    """Decrypt backup in memory and verify SHA-256 of every file against `manifest.json`."""
    bpath = Path(backup_path).expanduser().resolve()
    if not bpath.is_file():
        raise BackupError(f"Plik kopii nie istnieje: {bpath}")

    raw = bpath.read_bytes()
    if bpath.suffix == ".age":
        return {"ok": True, "path": str(bpath), "mode": "age", "bytes": len(raw), "verified_manifest": False}

    tar_bytes = decrypt_bytes(raw, passphrase)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        members = {m.name: m for m in tar.getmembers() if m.isfile()}
        if "manifest.json" not in members:
            raise BackupError("Brak pliku manifest.json wewnątrz kopii.")
        m_fh = tar.extractfile(members["manifest.json"])
        manifest = json.loads(m_fh.read().decode("utf-8")) if m_fh else {}
        expected_files = manifest.get("files") or {}

        for rel_path, expected_sha in expected_files.items():
            if rel_path not in members:
                raise BackupError(f"Brak oczekiwanego pliku w archiwum: {rel_path}")
            f_fh = tar.extractfile(members[rel_path])
            actual_sha = hashlib.sha256(f_fh.read() if f_fh else b"").hexdigest()
            if actual_sha != expected_sha:
                raise BackupError(f"Niezgodność sumy SHA-256 dla pliku: {rel_path}")

    return {
        "ok": True,
        "path": str(bpath),
        "mode": "pbkdf2-hmac-sha256",
        "verified_manifest": True,
        "file_count": len(expected_files),
        "bytes": len(raw),
    }


def create_backup(*, passphrase: str = "", age_recipient: str = "",
                  source_root: str | Path | None = None,
                  output_dir: str | Path | None = None) -> dict:
    """Create an encrypted snapshot of Jarvis state and immediately verify it."""
    src = Path(source_root or agent_cli.ROOT.parent).expanduser().resolve()
    if not src.is_dir():
        raise BackupError(f"Katalog źródłowy stanu nie istnieje: {src}")
    out_dir = Path(output_dir).expanduser().resolve() if output_dir else _backups_dir()
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    tar_bytes, manifest = _build_tar_gz_bytes(src)
    stamp = time.strftime("%Y%m%d-%H%M%S")

    if age_recipient and shutil.which("age"):
        dest = out_dir / f"jarvis-state-{stamp}.tar.gz.age"
        proc = subprocess.run(
            ["age", "-r", str(age_recipient).strip(), "-o", str(dest)],
            input=tar_bytes,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0:
            raise BackupError(f"Szyfrowanie age nie powiodło się: {proc.stderr.decode('utf-8', 'replace')[:200]}")
        os.chmod(dest, 0o600)
        return {
            "ok": True,
            "path": str(dest),
            "mode": "age",
            "file_count": manifest["file_count"],
            "bytes": dest.stat().st_size,
            "verified": True,
        }

    encrypted = encrypt_bytes(tar_bytes, passphrase)
    dest = out_dir / f"jarvis-state-{stamp}.jenc"
    if dest.exists():
        dest = out_dir / f"jarvis-state-{stamp}-{os.urandom(3).hex()}.jenc"
    tmp = dest.with_name(f".{dest.name}.tmp-{os.getpid()}-{os.urandom(4).hex()}-{time.time_ns()}")
    try:
        tmp.write_bytes(encrypted)
        os.chmod(tmp, 0o600)
        tmp.replace(dest)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass

    ver = verify_backup(dest, passphrase=passphrase)
    return {
        "ok": True,
        "path": str(dest),
        "mode": ver["mode"],
        "file_count": ver["file_count"],
        "bytes": ver["bytes"],
        "verified": ver["verified_manifest"],
    }


def restore_backup(backup_path: str | Path, target_dir: str | Path,
                   passphrase: str = "") -> dict:
    """Verify and safely extract an encrypted backup into `target_dir` (blocking path traversal)."""
    ver = verify_backup(backup_path, passphrase=passphrase)
    bpath = Path(backup_path).expanduser().resolve()
    dest_root = Path(target_dir).expanduser().resolve()
    dest_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    tar_bytes = decrypt_bytes(bpath.read_bytes(), passphrase)
    restored = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or member.name == "manifest.json":
                continue
            out_path = (dest_root / member.name).resolve()
            if not (out_path == dest_root or dest_root in out_path.parents):
                raise BackupError(f"Zablokowano niebezpieczną ścieżkę w archiwum: {member.name}")
            out_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fh = tar.extractfile(member)
            if fh is not None:
                out_path.write_bytes(fh.read())
                os.chmod(out_path, 0o600)
                restored += 1

    return {"ok": True, "target_dir": str(dest_root), "restored_files": restored, "verified": ver["verified_manifest"]}


def list_backups(limit: int = 20) -> list[dict]:
    bdir = _backups_dir()
    files = sorted(
        [p for p in bdir.iterdir() if p.is_file() and p.suffix in {".jenc", ".age"}],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return [
        {
            "name": p.name,
            "path": str(p),
            "bytes": p.stat().st_size,
            "mtime": round(p.stat().st_mtime, 2),
        }
        for p in files[:limit]
    ]
