"""Local operator capabilities for Jarvis.

The browser agent can be widened into a real local operator: shell, files,
desktop control through cua-driver, and a credential broker that can type a
secret without ever returning it to the model.  This module deliberately has no
Anthropic or Playwright dependency, so it can be unit-tested in isolation and a
missing desktop driver cannot stop Jarvis from booting.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import pty
import re
import select
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import document_extract
import net_guard
import ocr_backends
from atomic_io import atomic_write_text

HOME = Path.home()
# read_file returns at most this many bytes; the tool's visible text is capped
# far lower, but a single huge file must never be loaded into server RAM.
MAX_READ_BYTES = 8_000_000
# A foreground command's output is spooled to disk and read back only up to
# this bound. PIPE+communicate used to buffer an unbounded stream in memory.
MAX_TERMINAL_OUTPUT = 2_000_000
# A background command may run for hours; its log file must not fill the disk.
MAX_BACKGROUND_LOG = 16_000_000
PROJECT = Path(__file__).resolve().parent
VAULT = Path(os.environ.get("JARVIS_VAULT", str(Path.home() / "notes"))).expanduser()
TOOLS = HOME / ".jarvis-tools"
SECRETS_PATH = TOOLS / "secrets.json"
TRASH = TOOLS / "trash"
BACKUPS = TOOLS / "backups"
CUA_CANDIDATES = (
    Path(os.environ.get("JARVIS_CUA_DRIVER", "")) if os.environ.get("JARVIS_CUA_DRIVER") else None,
    HOME / ".hermes/tools/cua-driver-0.21.0-linux-x64/cua-driver",
    HOME / ".hermes/tools/cua-driver/cua-driver",
    Path("/usr/local/bin/cua-driver"),
    Path("/usr/bin/cua-driver"),
)
ALLOWED_ROOTS = (HOME, Path("/tmp"), Path("/mnt"), Path("/media"))
TESSERACT_CANDIDATES = (
    Path(os.environ.get("JARVIS_TESSERACT", "")) if os.environ.get("JARVIS_TESSERACT") else None,
    TOOLS / "opt/tesseract/bin/tesseract",
    Path("/usr/bin/tesseract"),
    Path("/usr/local/bin/tesseract"),
)
OCR_LANGS = {"eng", "pol", "osd", "deu", "fra", "spa", "ita", "ukr"}
# `--list-langs` is a full process spawn per OCR call; installed languages only
# change when a language pack is installed, so a bounded TTL is plenty.
OCR_LANGS_TTL = 900.0
_OCR_LANGS_CACHE: dict[str, tuple[float, list[str]]] = {}
_OCR_LANGS_LOCK = threading.Lock()
SENSITIVE_PARTS = {
    ".ssh", ".gnupg", ".password-store", ".hermes/.env", ".env",
    ".config/google-chrome", ".config/chromium", ".mozilla", "config.json",
    # Common cloud/package credentials that were previously readable.
    ".aws", ".docker/config.json", ".kube/config", ".git-credentials",
    ".npmrc", ".pypirc", ".config/gh", ".config/gcloud",
    # Persistence surfaces: shell startup, autostart and user services. A
    # prompt-injected Standard-mode write here would survive a reboot.
    ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv",
    ".xprofile", ".xsessionrc", ".gitconfig", ".config/autostart",
    ".config/systemd", ".config/environment.d", ".local/share/applications",
}
# The state root itself is needed for backups/trash/documents; only the
# control files and private subtrees are protected from the Operator.
JARVIS_CONTROL = {
    "agent-mode.json", "agent-queue.json", "agent-history.json", "schedules.json",
    "undo.json", "secrets.json", "mcp.json", "memory.db", "sessions.db",
    "memory-vectors.db", "embeddings.db",
}
JARVIS_PRIVATE_DIRS = {"selfmod", "plans", "agent", "rea"}


def real_path(path) -> Path:
    """Canonical target path: symlinks must not hide a sensitive destination."""
    try:
        return Path(os.path.realpath(str(path)))
    except (OSError, ValueError):
        return Path(str(path))


def is_sensitive_target(path) -> bool:
    """Sensitive check on the resolved target, not on the lexical path."""
    return is_sensitive(real_path(path))


def is_credential_target(path) -> bool:
    """Reads refuse credentials and control files, not the job's own artifacts.

    ``is_sensitive`` intentionally covers the whole state root, which is right
    for writes. For reads that would also hide the screenshots, downloads and
    plan files the Operator just produced, so those private subtrees stay
    readable while ``secrets.json``, the queue and the vector databases do not.
    """
    resolved = real_path(path)
    if not is_sensitive(resolved):
        return False
    parts = [part.casefold() for part in Path(str(resolved)).parts]
    try:
        index = parts.index(".jarvis-tools")
    except ValueError:
        return True
    rest = parts[index + 1:]
    if rest and rest[0] in JARVIS_PRIVATE_DIRS:
        return any(name.casefold() in {item.casefold() for item in JARVIS_CONTROL}
                   for name in rest)
    return True
DANGEROUS_COMMAND = re.compile(
    r"(?im)(?:^|[\n;&|`$({]\s*|&&\s*)\s*(?:"
    r"(?:/[\w./-]+/)?(?:sudo|doas)\b|"
    r"(?:/[\w./-]+/)?rm\s+[^\n;&|]*(?:--recursive|--force|-[A-Za-z]*[rRf])|"
    r"(?:/[\w./-]+/)?(?:mkfs\S*|dd\s+if=|shutdown|reboot|poweroff|halt)\b|"
    r"kill\s+-9\s+1\b|"
    r"systemctl\s+(?:--user\s+)?(?:disable|stop|restart|mask|poweroff|reboot)\b|"
    r"chmod\s+777\s+/|chown\s+[^ ]+\s+/|"
    r"(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh|python\d?)\b|"
    r"(?:/[\w./-]+/)?sh\s+-c\s+[^;\n]*(?:rm\s|sudo\b)|"
    r"git\s+push\s+--force|git\s+reset\s+--hard|git\s+clean\s+-fdx|"
    r"npm\s+publish|pip\s+uninstall\s+-y)",
    re.I,
)
# Obvious data-egress commands. Standard mode asks before these, because a
# prompt-injected page plus a readable file is a one-step exfiltration path.
EGRESS_COMMAND = re.compile(
    r"(?im)(?:^|[\n;&|`$({]\s*|&&\s*)\s*(?:"
    r"(?:/[\w./-]+/)?(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|ftp|telnet)\b|"
    r"python\d?\s+-c\s+[^\n]*(?:socket|urllib|requests|httpx))",
    re.I,
)
# A command can hide its real work behind a wrapper: `bash -c 'curl ...'`,
# `env curl ...`, `nohup wget ...`, `xargs curl ...`, `timeout 10 curl ...`.
# These regexes widen the approval gate conservatively; a false positive only
# asks the human, while a false negative is unapproved exfiltration.
SHELL_WRAPPER = re.compile(
    r"(?im)(?:^|[\s;|&])(?:"
    r"(?:/[\w./-]+/)?(?:ba|z|da|k|fi)?sh(?:\s|$)|"
    r"(?:/[\w./-]+/)?(?:env|nohup|xargs|timeout|setsid|stdbuf|command|exec)\b|"
    r"python\d?\s+-c\b|perl\s+-e\b|ruby\s+-e\b)",
    re.I,
)
EGRESS_BINARY = re.compile(
    r"(?i)\b(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|ftp|telnet)\b")
DESTRUCTIVE_BINARY = re.compile(
    r"(?i)\b(?:sudo|doas|rm|mkfs\S*|dd|shutdown|reboot|poweroff|halt|"
    r"systemctl|chmod|chown|npm|pip)\b")
PYTHON_NETWORK = re.compile(
    r"(?is)python\d?\s+-c\b[^\n]*(?:socket|urllib|requests|httpx)")


def egress_risk(command) -> bool:
    """True when a command can send data, including behind shell wrappers."""
    text = str(command or "")
    if EGRESS_COMMAND.search(text) or PYTHON_NETWORK.search(text):
        return True
    return bool(SHELL_WRAPPER.search(text) and EGRESS_BINARY.search(text))


def destructive_risk(command) -> bool:
    """True for clearly destructive commands, including wrapper payloads."""
    text = str(command or "")
    if DANGEROUS_COMMAND.search(text):
        return True
    return bool(SHELL_WRAPPER.search(text) and DESTRUCTIVE_BINARY.search(text))
# Environment names that change where bash or python look for code, libraries,
# startup files or trust anchors; allowing the model to set them was code
# execution by another name (BASH_ENV, LD_PRELOAD, PATH ...).
RESERVED_ENV_KEYS = {
    "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV", "IFS", "SHELL",
    "SHELLOPTS", "BASHOPTS", "HOME", "TMPDIR", "PYTHONPATH", "PYTHONSTARTUP",
    "PYTHONHOME", "GCONV_PATH", "GIT_ASKPASS", "GIT_SSH", "SSH_AUTH_SOCK",
    "PERL5OPT", "GZIP", "RSYNC_RSH", "SUDO_ASKPASS", "SYSTEMD_UNIT_PATH",
}
SECRET_PATTERN = re.compile(
    r"(?:\bsk-(?:or|ant)-[A-Za-z0-9_-]{8,}|"
    r"\bsk-[A-Za-z0-9_-]{16,}|"
    r"\bgsk_[A-Za-z0-9_-]{16,}|"
    r"\bgh[pousr]_[A-Za-z0-9_]{20,}|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}|"
    r"\bAKIA[A-Z0-9]{16}\b|"
    r"\bBearer\s+\S+|"
    r"(?:api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]{4,}|"
    r"x-api-key\s*[:=]\s*\S+)",
    re.I,
)
# A PEM key is a block, not a line: matching only the BEGIN header used to
# leave the base64 body in tool output. An unterminated block is redacted to
# the end of the text rather than leaking the remainder.
PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    re.S,
)


class ToolError(Exception):
    """A safe, public tool failure."""


_SECRET_ENV_NAME = re.compile(r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)", re.I)
_SECRET_ENV_VALUES: tuple[str, ...] | None = None


def _secret_env_values() -> tuple[str, ...]:
    """Values of secret-looking environment variables, longest first.

    ``env``, ``printenv`` or a crashing script used to hand the model the
    provider keys this process inherited (DEEPSEEK_API_KEY and friends); the
    pattern list only recognised well-known token shapes.
    """
    global _SECRET_ENV_VALUES
    if _SECRET_ENV_VALUES is None:
        values = {value for name, value in os.environ.items()
                  if isinstance(value, str) and len(value) >= 12
                  and _SECRET_ENV_NAME.search(name)}
        _SECRET_ENV_VALUES = tuple(sorted(values, key=len, reverse=True))
    return _SECRET_ENV_VALUES


def redact(text: Any, limit: int = 12000) -> str:
    value = str(text or "")
    value = PEM_PRIVATE_KEY.sub("[REDACTED]", value)
    value = SECRET_PATTERN.sub("[REDACTED]", value)
    for secret in _secret_env_values():
        if secret in value:
            value = value.replace(secret, "[REDACTED]")
    value = value.replace(str(HOME) + "/", "~/")
    return value[:limit]


def _inside(path: Path, roots=ALLOWED_ROOTS) -> bool:
    try:
        resolved = path.resolve()
        return any(resolved == root.resolve() or resolved.is_relative_to(root.resolve()) for root in roots)
    except (OSError, RuntimeError):
        return False


def resolve_path(raw: Any, *, base: Path = HOME, must_exist: bool = False) -> Path:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 4096:
        raise ToolError("A file path must be non-empty text.")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = base / path
    if any(part in ("..", "") for part in path.parts):
        raise ToolError("Parent-directory paths are not accepted.")
    if not _inside(path):
        raise ToolError("That path is outside the allowed home/temp/media roots.")
    if must_exist and not path.exists():
        raise ToolError("That path does not exist.")
    return path


def _sensitive_name(actual: str, wanted: str) -> bool:
    """Whole-name matching with the common real renames.

    ``.env`` matches ``.env``, ``.env.local`` and ``.env-old``, and no longer
    the old substring hits like ``note_take.env109.txt`` or ``archive.env7``.
    """
    return (actual == wanted
            or (actual.startswith(wanted) and actual[len(wanted):len(wanted) + 1] in ".-_")
            or (wanted.startswith(".") and actual.endswith(wanted)))


def is_sensitive(path: Path) -> bool:
    """Path-component match over SENSITIVE_PARTS.

    Substring matching used to block innocent files whose name merely contained
    a sensitive fragment; entries spanning directories (.hermes/.env) must now
    line up as consecutive path components.
    """
    parts = [part.casefold() for part in Path(str(path)).parts]
    for index, part in enumerate(parts):
        if part != ".jarvis-tools":
            continue
        rest = parts[index + 1:]
        if not rest or rest[0] in JARVIS_PRIVATE_DIRS or rest[0] in JARVIS_CONTROL:
            return True
        # embeddings-<vault>.db files sit directly in the state root.
        if rest[0].startswith("embeddings-") and rest[0].endswith(".db"):
            return True
    for entry in SENSITIVE_PARTS:
        wanted = [part.casefold() for part in entry.split("/")]
        size = len(wanted)
        for index in range(len(parts) - size + 1):
            window = parts[index:index + size]
            if all(_sensitive_name(actual, expect) for actual, expect in zip(window, wanted)):
                return True
    return False


def format_size(size: int) -> str:
    value = float(size)
    for suffix in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024:
            return f"{value:.1f} {suffix}"
        value /= 1024
    return f"{value:.1f} PB"



@dataclass
class FileOps:
    workspace: Path = HOME

    def read(self, path: str, offset: int = 0, limit: int = 12000) -> dict:
        target = resolve_path(path, base=self.workspace, must_exist=True)
        # write/delete/copy already refuse these; read used to return the bytes
        # with only a "sensitive" flag, so a prompt-injected job could pull
        # ~/.ssh, cloud credentials or the app's own secrets.json into context.
        if is_credential_target(target):
            raise ToolError("That path is protected; use a dedicated secret tool.")
        if target.is_dir():
            raise ToolError("That path is a directory; use list_dir.")
        if document_extract.is_supported(target):
            doc_offset = max(0, int(offset or 0))
            doc_limit = max(1, min(int(limit or 12000), 40000))
            try:
                document = document_extract.extract_document(
                    target, min(200_000, max(40_000, doc_offset + doc_limit)))
            except document_extract.DocumentError:
                document = None
            if document is not None:
                text = document["text"]
                doc_offset = min(doc_offset, len(text))
                return {"path": str(target), "bytes": document["bytes"],
                        "format": document["format"], "total_chars": len(text),
                        "offset": doc_offset,
                        "text": redact(text[doc_offset:doc_offset + doc_limit], doc_limit),
                        "truncated": document["truncated"] or doc_offset + doc_limit < len(text),
                        "sensitive": is_sensitive_target(target)}
        data = b""
        size = 0
        oversized = False
        try:
            # O_NONBLOCK makes a FIFO open/read return instead of hanging the
            # operator thread; fstat then rejects anything that is not a
            # regular file. The bounded read keeps a multi-GB file out of RAM.
            flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(target, flags)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise ToolError("Only regular files can be read; this path is a device, pipe or socket.")
                size = info.st_size
                chunks = []
                remaining = MAX_READ_BYTES + 1
                while remaining > 0:
                    chunk = os.read(fd, min(1 << 20, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
            finally:
                os.close(fd)
        except ToolError:
            raise
        except OSError as error:
            raise ToolError(f"The file could not be read: {type(error).__name__}.") from None
        if len(data) > MAX_READ_BYTES:
            oversized = True
            data = data[:MAX_READ_BYTES]
        if b"\0" in data[:4096]:
            return {"path": str(target), "bytes": size, "binary": True,
                    "message": "Binary file; use terminal for a format-specific tool."}
        text = data.decode("utf-8", errors="replace")
        offset = max(0, min(int(offset or 0), len(text)))
        limit = max(1, min(int(limit or 12000), 40000))
        return {"path": str(target), "bytes": size, "total_chars": len(text),
                "offset": offset, "text": redact(text[offset:offset + limit], limit),
                "truncated": oversized or offset + limit < len(text),
                "sensitive": is_sensitive_target(target)}

    def write(self, path: str, content: str, append: bool = False) -> dict:
        if not isinstance(content, str) or len(content) > 2_000_000:
            raise ToolError("File content must be text under 2,000,000 characters.")
        target = resolve_path(path, base=self.workspace)
        if target.is_symlink() or is_sensitive_target(target):
            raise ToolError("That path is protected; use a dedicated secret tool.")
        backup = None
        try:
            if append:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("a", encoding="utf-8") as handle:
                    handle.write(content)
            else:
                existing_mode = (target.stat().st_mode & 0o777) if target.is_file() else 0o644
                backup = atomic_write_text(
                    target, content, mode=existing_mode, dir_mode=None, backup_dir=BACKUPS
                )
        except OSError as error:
            raise ToolError(f"The file could not be written: {type(error).__name__}.") from None
        return {"path": str(target), "bytes": target.stat().st_size, "appended": bool(append),
                "backup": str(backup) if backup else None}

    def list(self, path: str = "~", depth: int = 1) -> dict:
        target = resolve_path(path, base=self.workspace, must_exist=True)
        if not target.is_dir():
            raise ToolError("That path is not a directory.")
        if is_sensitive_target(target):
            raise ToolError("That directory is protected.")
        depth = max(1, min(int(depth or 1), 3))
        rows: list[dict] = []

        def walk(folder: Path, level: int):
            try:
                children = sorted(folder.iterdir(), key=lambda item: (not item.is_dir(), item.name.casefold()))
            except OSError:
                return
            for child in children[:250]:
                if is_sensitive_target(child):
                    continue
                rel = str(child.relative_to(target)) if child != target else child.name
                rows.append({"path": rel, "name": child.name, "dir": child.is_dir(),
                             "bytes": child.stat().st_size if child.is_file() else None})
                if child.is_dir() and level < depth and not child.is_symlink():
                    walk(child, level + 1)

        walk(target, 1)
        return {"path": str(target), "entries": rows[:500], "truncated": len(rows) > 500}

    def search(self, pattern: str, path: str = "~", file_glob: str = "*", limit: int = 60) -> dict:
        if not isinstance(pattern, str) or not pattern or len(pattern) > 300:
            raise ToolError("A search pattern is required.")
        target = resolve_path(path, base=self.workspace, must_exist=True)
        if is_sensitive_target(target):
            raise ToolError("That path is protected.")
        limit = max(1, min(int(limit or 60), 200))
        try:
            expression = re.compile(pattern)
        except re.error:
            raise ToolError("The search pattern is not a valid regular expression.") from None
        hits: list[dict] = []
        files = [target] if target.is_file() else target.rglob(file_glob or "*")
        inspected = 0
        for candidate in files:
            if len(hits) >= limit or inspected >= 5000:
                break
            inspected += 1
            try:
                if (candidate.is_symlink() or not candidate.is_file()
                        or is_sensitive_target(candidate)
                        or candidate.stat().st_size > 2_000_000):
                    continue
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if expression.search(line):
                    hits.append({"path": str(candidate), "line": number,
                                 "text": redact(line.strip(), 500)})
                    if len(hits) >= limit:
                        break
        return {"path": str(target), "pattern": pattern, "hits": hits, "truncated": len(hits) >= limit}

    def restore(self, backup: str, path: str) -> dict:
        # resolve() BEFORE the containment check: a symlink planted inside the
        # backups folder used to pass `relative_to` and copy any host file.
        source = resolve_path(backup, must_exist=True)
        if source.is_symlink():
            raise ToolError("That backup path is a symlink; refusing to restore it.")
        source = Path(os.path.realpath(source))
        try:
            source.relative_to(Path(os.path.realpath(BACKUPS)))
        except ValueError:
            raise ToolError("That path is not in the Jarvis backup folder.") from None
        if not source.is_file() or is_sensitive_target(source):
            raise ToolError("That backup is not a restorable file.")
        target = resolve_path(path, base=self.workspace)
        if target.is_symlink() or is_sensitive_target(target):
            raise ToolError("That target path is protected.")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        except OSError as error:
            raise ToolError(f"The backup could not be restored: {type(error).__name__}.") from None
        return {"ok": True, "backup": str(source), "path": str(target),
                "bytes": target.stat().st_size}

    def delete(self, path: str) -> dict:
        target = resolve_path(path, base=self.workspace, must_exist=True)
        if target == HOME or target == VAULT or target == PROJECT:
            raise ToolError("Refusing to delete a protected root.")
        if is_sensitive_target(target):
            raise ToolError("That path is protected.")
        try:
            TRASH.mkdir(parents=True, exist_ok=True)
            destination = TRASH / f"{int(time.time())}-{uuid.uuid4().hex[:8]}-{target.name}"
            shutil.move(str(target), str(destination))
        except OSError as error:
            raise ToolError(f"The path could not be moved to trash: {type(error).__name__}.") from None
        return {"path": str(target), "trash": str(destination), "recoverable": True}


class Pdf:
    """Extract text from a PDF with the system pdftotext tool."""

    def text(self, path: str, pages: int = 40) -> dict:
        target = resolve_path(path, must_exist=True)
        if is_sensitive_target(target):
            raise ToolError("That path is protected.")
        if target.suffix.casefold() != ".pdf" or not target.is_file():
            raise ToolError("That path is not a PDF file.")
        if not shutil.which("pdftotext"):
            raise ToolError("pdftotext is not installed; PDF reading is unavailable.")
        pages = max(1, min(int(pages or 40), 200))
        try:
            result = subprocess.run(
                ["pdftotext", "-layout", "-f", "1", "-l", str(pages), str(target), "-"],
                capture_output=True, text=True, timeout=60,
            )
        except subprocess.TimeoutExpired:
            raise ToolError("The PDF text extraction timed out.") from None
        if result.returncode != 0:
            raise ToolError("The PDF could not be read.")
        text = result.stdout or ""
        return {"ok": True, "path": str(target), "pages": pages,
                "text": redact(text, 20000), "chars": len(text), "truncated": len(text) > 20000}


def find_tesseract() -> Path | None:
    for candidate in TESSERACT_CANDIDATES:
        if candidate and candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


class Ocr:
    """Read text out of a screenshot or photo with a local tesseract binary."""

    def __init__(self, binary: Path | None = None):
        self.binary = binary or find_tesseract()

    def available(self) -> bool:
        return self.binary is not None

    def languages(self) -> list[str]:
        if not self.binary:
            return []
        key = str(self.binary)
        with _OCR_LANGS_LOCK:
            cached = _OCR_LANGS_CACHE.get(key)
            if cached and time.monotonic() - cached[0] < OCR_LANGS_TTL:
                return list(cached[1])
        try:
            result = subprocess.run([str(self.binary), "--list-langs"], capture_output=True,
                                    text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            return []
        lines = [line.strip() for line in (result.stdout or "").splitlines()]
        found = [line for line in lines if re.fullmatch(r"[a-z]{3}(?:_[a-z]+)?", line)]
        if found:  # a transient empty read is not worth remembering
            with _OCR_LANGS_LOCK:
                _OCR_LANGS_CACHE[key] = (time.monotonic(), found)
        return list(found)

    IMAGE_SUFFIXES = frozenset(
        {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp", ".gif", ".pnm"})

    def _validate_image(self, target: Path) -> Path:
        """The shared image gate for both tesseract entry points."""
        if not target.is_file():
            raise ToolError("That path is not an image file.")
        if target.suffix.casefold() not in self.IMAGE_SUFFIXES:
            raise ToolError("Unsupported image type; use png, jpg, bmp, tif, webp or gif.")
        if not self.binary:
            raise ToolError("No local tesseract binary is installed; OCR is unavailable.")
        return target

    def _usable_langs(self, langs: str, default: str) -> list[str]:
        """The shared language gate: whitelist first, then what is installed."""
        requested = [part.strip() for part in str(langs or default).split("+") if part.strip()]
        if not requested or any(part not in OCR_LANGS for part in requested):
            raise ToolError("Unsupported OCR language; choose from "
                            + ", ".join(sorted(OCR_LANGS)) + ".")
        installed = set(self.languages())
        usable = [part for part in requested if part in installed]
        if not usable:
            raise ToolError("None of the requested OCR languages are installed ("
                            + ", ".join(requested) + ").")
        return usable

    def _prepare_target(self, path: str) -> Path:
        target = resolve_path(path, must_exist=True)
        if is_sensitive_target(target):
            raise ToolError("That path is protected.")
        return self._validate_image(target)

    def _run_tesseract(self, target: Path, langs: str, psm: int, default_psm: int,
                       extra_args: tuple[str, ...] = ()) -> tuple[list[str], str]:
        """Shared tesseract execution gate for plain text and TSV layout passes."""
        usable = self._usable_langs(langs, "eng")
        try:
            clamped_psm = max(0, min(int(psm if psm is not None else default_psm), 13))
        except (TypeError, ValueError):
            raise ToolError("OCR psm must be an integer between 0 and 13.") from None
        argv = [str(self.binary), str(target), "stdout", "-l", "+".join(usable),
                "--psm", str(clamped_psm), *extra_args]
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            raise ToolError("The OCR pass timed out.") from None
        except OSError:
            raise ToolError("The local tesseract binary could not be started.") from None
        if result.returncode != 0:
            raise ToolError("The image could not be read by tesseract.")
        return usable, (result.stdout or "")

    def text(self, path: str, langs: str = "eng+pol", psm: int = 3, engine: str = "tesseract") -> dict:
        target = self._prepare_target(path)
        engine = str(engine or "tesseract").lower()
        if engine in ("surya", "auto"):
            found = ocr_backends.text(str(target))
            if found:
                words = [word for word in found["text"].split() if word.strip()]
                return {"ok": True, "path": str(target), "languages": ["surya"], "engine": "surya",
                        "text": redact(found["text"], 20000), "chars": found["chars"],
                        "words": len(words), "empty": not words,
                        "truncated": found["chars"] > 20000}
            if engine == "surya":
                state = ocr_backends.status(probe=True)
                detail = state.get("error") or ("no OCR venv" if not state.get("installed")
                                                else "surya venv present but unusable")
                raise ToolError(f"surya OCR is not ready on this host ({detail}).")
        usable, text = self._run_tesseract(target, langs, psm, default_psm=3)
        words = [word for word in text.split() if word.strip()]
        return {"ok": True, "path": str(target), "languages": usable,
                "text": redact(text, 20000), "chars": len(text), "words": len(words),
                "empty": not words, "truncated": len(text) > 20000, "engine": "tesseract"}

    def layout(self, path: str, langs: str = "eng+pol", psm: int = 6) -> dict:
        """Read an image as text blocks with positions and confidence.

        Tesseract's TSV mode is the cheap layout upgrade: the model gets lines
        grouped by block instead of one undifferentiated string, which matters
        for tables, forms and screenshots.
        """
        target = self._prepare_target(path)
        usable, stdout = self._run_tesseract(target, langs, psm, default_psm=6, extra_args=("tsv",))
        rows = [line.split("\t") for line in stdout.splitlines()[1:] if line.count("\t") >= 11]
        blocks = {}
        for row in rows:
            try:
                level, block, par, line = (int(row[0]), int(row[2]), int(row[3]), int(row[4]))
                left, top, width, height = (int(row[6]), int(row[7]), int(row[8]), int(row[9]))
                conf = float(row[10])
                text = row[11].strip()
            except (ValueError, IndexError):
                continue
            if level != 5 or not text or conf < 30:
                continue
            key = (block, par, line)
            entry = blocks.setdefault(key, {"block": block, "line": line, "bbox": [left, top, left + width, top + height],
                                             "words": [], "confidence": round(conf / 100, 3)})
            entry["words"].append(text)
            entry["bbox"][2] = max(entry["bbox"][2], left + width)
            entry["bbox"][3] = max(entry["bbox"][3], top + height)
        lines = []
        for key in sorted(blocks):
            entry = blocks[key]
            lines.append({"block": entry["block"], "line": entry["line"], "bbox": entry["bbox"],
                          "text": " ".join(entry["words"])[:300], "confidence": entry["confidence"]})
        lines = lines[:200]
        text = "\n".join(item["text"] for item in lines)
        return {"ok": True, "path": str(target), "languages": usable, "engine": "tesseract-layout",
                "lines": lines, "blocks": len({item["block"] for item in lines}),
                "text": redact(text, 20000), "chars": len(text), "empty": not lines}



def _stop_process_group(process) -> None:
    """Terminate a start_new_session child and its descendants."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        pass
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        process.wait(timeout=2)
    except (subprocess.TimeoutExpired, OSError):
        pass


def stop_background_group(pid: int, command: str = "", grace: float = 2.0) -> None:
    """Stop a background shell's process group without harming a reused pid."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return
    if pid <= 1 or pid == os.getpid():
        return

    def still_ours() -> bool:
        if not command:
            return True
        try:
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return False
        return command.encode("utf-8", "replace") in raw

    if not still_ours():
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except OSError:
        return
    deadline = time.monotonic() + max(0.0, grace)
    while time.monotonic() < deadline:
        try:
            os.killpg(pid, 0)
        except OSError:
            return
        time.sleep(0.05)
    try:
        # The leader may have exited while children remain in its saved group;
        # killpg still reaches them. The initial argv check prevented acting on
        # a plainly reused pid; a 2s group-id reuse is not realistic.
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass


class Terminal:
    def __init__(self, workspace: Path = HOME):
        self.workspace = workspace

    @staticmethod
    def risk(command: str) -> bool:
        return destructive_risk(command)

    def run(self, command: str, cwd: str | None = None, timeout: int = 120, background: bool = False,
            env_extra: dict | None = None, cancel_event=None) -> dict:
        if not isinstance(command, str) or not command.strip() or len(command) > 20000:
            raise ToolError("A command must be non-empty text under 20,000 characters.")
        workdir = resolve_path(cwd or str(self.workspace), base=self.workspace, must_exist=True)
        if not workdir.is_dir():
            raise ToolError("The working directory is not a directory.")
        timeout = max(1, min(int(timeout or 120), 300))
        environment = {**os.environ, "PWD": str(workdir)}
        for key, value in (env_extra or {}).items():
            upper = str(key).upper()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,80}", str(key)) and upper not in RESERVED_ENV_KEYS:
                environment[str(key)] = str(value)
        started = time.monotonic()
        argv = ["/bin/bash", "-lc", command]
        if background:
            log = TOOLS / "background" / f"{int(time.time())}-{uuid.uuid4().hex[:8]}.log"
            log.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with log.open("ab") as handle:
                try:
                    os.chmod(log, 0o600)
                except OSError:
                    pass
                process = subprocess.Popen(
                    argv, cwd=str(workdir), stdin=subprocess.DEVNULL,
                    stdout=handle, stderr=subprocess.STDOUT, start_new_session=True,
                    env=environment,
                )

            def watch_background():
                killed = False
                while process.poll() is None:
                    try:
                        if log.stat().st_size > MAX_BACKGROUND_LOG:
                            killed = True
                            _stop_process_group(process)
                            break
                    except OSError:
                        pass
                    time.sleep(0.5)
                try:
                    process.wait(timeout=2)
                except (subprocess.TimeoutExpired, OSError):
                    pass
                if killed:
                    try:
                        with log.open("a", encoding="utf-8") as tail:
                            tail.write("\n[jarvis] background log limit reached; process stopped.\n")
                    except OSError:
                        pass

            threading.Thread(target=watch_background, daemon=True,
                             name="jarvis-bg-reaper").start()
            return {"ok": True, "pid": process.pid, "log": str(log),
                    "cwd": str(workdir), "background": True}
        process = None
        spool = tempfile.TemporaryFile()
        overflow = False
        try:
            process = subprocess.Popen(
                argv, cwd=str(workdir), stdin=subprocess.DEVNULL,
                stdout=spool, stderr=subprocess.STDOUT, start_new_session=True,
                env=environment,
            )
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if cancel_event is not None and cancel_event.is_set():
                    _stop_process_group(process)
                    raise ToolError("The command was stopped by the user.")
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(command, timeout)
                try:
                    size = os.fstat(spool.fileno()).st_size
                except OSError:
                    size = 0
                if size > MAX_TERMINAL_OUTPUT:
                    overflow = True
                    _stop_process_group(process)
                    break
                time.sleep(0.05)
            spool.seek(0)
            output = spool.read(MAX_TERMINAL_OUTPUT + 1)
        except subprocess.TimeoutExpired:
            if process is not None and process.poll() is None:
                _stop_process_group(process)
            raise ToolError(f"The command exceeded its {timeout}s timeout and was stopped.") from None
        finally:
            spool.close()
        elapsed = round(time.monotonic() - started, 3)
        text = output.decode("utf-8", errors="replace") if output else ""
        if len(text) > MAX_TERMINAL_OUTPUT:
            overflow = True
            text = text[:MAX_TERMINAL_OUTPUT]
        result = {"ok": process.returncode == 0 and not overflow,
                  "exit_code": process.returncode,
                  "output": redact(text, 12000), "truncated": overflow or len(text) > 12000,
                  "cwd": str(workdir), "seconds": elapsed,
                  "dangerous": self.risk(command)}
        if overflow:
            result["error"] = "output_too_large"
        return result


def find_cua() -> Path | None:
    for candidate in CUA_CANDIDATES:
        if candidate and candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


class CuaDriver:
    """Small JSON subprocess bridge to the installed cua-driver daemon."""

    def __init__(self, binary: Path | None = None):
        self.binary = binary or find_cua()
        self.last: dict[str, dict] = {}
        self._started = False

    def available(self) -> bool:
        return self.binary is not None

    def _start_daemon(self, force: bool = False) -> None:
        if not self.binary or (self._started and not force):
            return
        socket = HOME / ".cache/cua-driver/cua-driver.sock"
        socket.parent.mkdir(parents=True, exist_ok=True)
        if force:
            # A daemon can survive its session and then accept the socket while
            # never answering ("daemon closed connection without response").
            # Killing it and removing the socket is the only way back.
            self._stop_daemon(socket)
        self._started = True
        try:
            subprocess.Popen(
                [str(self.binary), "serve", "--permission-mode", "standard", "--socket", str(socket)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            time.sleep(1.2)
        except OSError:
            pass

    @staticmethod
    def _is_daemon_process(pid: int) -> bool:
        try:
            parts = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        except OSError:
            return False
        args = [part.decode("utf-8", "replace") for part in parts if part]
        # Only the daemon itself: a shell command line that merely mentions
        # "cua-driver serve" (a test or a wrapper) must never be killed.
        return bool(args) and Path(args[0]).name == "cua-driver" and "serve" in args[1:]

    def _stop_daemon(self, socket: Path) -> None:
        pids: set[int] = set()
        try:
            pids.add(int((socket.parent / "cua-driver.pid").read_text().strip()))
        except (OSError, ValueError):
            pass
        try:
            found = subprocess.run(["pgrep", "-f", str(socket)], capture_output=True,
                                   text=True, timeout=5)
            pids.update(int(line) for line in found.stdout.split() if line.strip().isdigit())
        except (OSError, subprocess.SubprocessError):
            pass
        live = [pid for pid in pids if pid != os.getpid() and self._is_daemon_process(pid)]
        for pid in live:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        time.sleep(0.4)
        for pid in live:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        for target in (socket, socket.parent / "cua-driver.pid"):
            try:
                target.unlink()
            except OSError:
                pass

    def call(self, tool: str, arguments: dict | None = None, timeout: int = 60) -> dict:
        if not self.binary:
            raise ToolError("cua-driver is not installed; desktop control is unavailable.")
        if not re.fullmatch(r"[A-Za-z0-9_]+", tool or ""):
            raise ToolError("Invalid desktop tool.")
        argv = [str(self.binary), "call", tool, "--json"]
        if arguments:
            argv.append(json.dumps(arguments, ensure_ascii=False))
        result = None
        for attempt in range(2):
            try:
                result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            except subprocess.TimeoutExpired:
                raise ToolError("The desktop driver timed out.") from None
            if result.returncode == 0:
                break
            message = (result.stderr or result.stdout or "").lower()
            if attempt == 0 and ("daemon" in message or "socket" in message or "connection" in message):
                self._start_daemon(force=True)
                continue
            break
        raw = (result.stdout or "").strip() if result is not None else ""
        if result is None or result.returncode != 0:
            message = (result.stderr or raw or "The desktop driver refused the request.").strip() if result else ""
            raise ToolError(redact(message, 800))
        if not raw:
            return {"ok": True}
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return {"ok": True, "text": redact(raw, 8000)}
        if isinstance(payload, dict) and payload.get("error"):
            raise ToolError(redact(payload["error"], 800))
        return payload

    def windows(self) -> list[dict]:
        payload = self.call("list_windows", {"on_screen_only": False}, timeout=20)
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        windows = data.get("windows", data if isinstance(data, list) else [])
        return [w for w in windows if isinstance(w, dict)]

    def apps(self) -> list[dict]:
        payload = self.call("list_apps", {}, timeout=20)
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        apps = data.get("apps", [])
        return [item for item in apps if isinstance(item, dict) and item.get("running")]

    def capture(self, pid: int, window_id: int, screenshot: Path | None = None) -> dict:
        args = {"pid": int(pid), "window_id": int(window_id), "include_screenshot": bool(screenshot),
                "max_elements": 140, "max_depth": 18}
        if screenshot:
            args["screenshot_out_file"] = str(screenshot)
        payload = self.call("get_window_state", args, timeout=90)
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        self.last[f"{pid}:{window_id}"] = data
        structured = data.get("structuredContent") or {}
        elements = structured.get("elements") or data.get("elements") or []
        tree = data.get("tree_markdown") or structured.get("tree_markdown") or ""
        return {"ok": True, "pid": int(pid), "window_id": int(window_id),
                "snapshot_id": data.get("snapshot_id") or structured.get("snapshot_id"),
                "elements": elements[:140], "tree": redact(tree, 8000),
                "screenshot": str(screenshot) if screenshot else None,
                "element_count": len(elements)}

    def click(self, pid: int, window_id: int, *, element: int | None = None,
              x: float | None = None, y: float | None = None) -> dict:
        args: dict[str, Any] = {"pid": int(pid), "window_id": int(window_id)}
        if element is not None:
            snapshot = self.last.get(f"{pid}:{window_id}", {})
            if snapshot.get("snapshot_id"):
                args["snapshot_id"] = snapshot["snapshot_id"]
            args["element_index"] = int(element)
        elif x is not None and y is not None:
            args.update({"x": float(x), "y": float(y)})
        else:
            raise ToolError("A desktop click needs an element index or x/y coordinates.")
        return self.call("click", args)

    def type(self, pid: int, window_id: int, text: str, *, element: int | None = None) -> dict:
        args: dict[str, Any] = {"pid": int(pid), "window_id": int(window_id), "text": text}
        if element is not None:
            snapshot = self.last.get(f"{pid}:{window_id}", {})
            if snapshot.get("snapshot_id"):
                args["snapshot_id"] = snapshot["snapshot_id"]
            args["element_index"] = int(element)
        return self.call("type_text", args, timeout=90)

    def key(self, pid: int, window_id: int, keys: str) -> dict:
        parts = [part for part in re.split(r"\s*\+\s*", keys or "") if part]
        if not parts:
            raise ToolError("A key or key combination is required.")
        if len(parts) == 1:
            return self.call("press_key", {"pid": int(pid), "window_id": int(window_id), "key": parts[0]})
        return self.call("hotkey", {"pid": int(pid), "window_id": int(window_id), "keys": parts})

    def scroll(self, pid: int, window_id: int, direction: str = "down", amount: int = 3) -> dict:
        if direction not in ("up", "down", "left", "right"):
            raise ToolError("Desktop scroll direction must be up, down, left or right.")
        return self.call("scroll", {"pid": int(pid), "window_id": int(window_id),
                                    "direction": direction, "amount": max(1, min(int(amount), 50))})

    def launch(self, name: str) -> dict:
        return self.call("launch_app", {"name": name}, timeout=30)

    def focus(self, pid: int, window_id: int) -> dict:
        return self.call("bring_to_front", {"pid": int(pid), "window_id": int(window_id)})

    def desktop_screenshot(self, path: Path) -> dict:
        return self.call("get_desktop_state", {"screenshot_out_file": str(path)}, timeout=60)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Validate every redirect hop and never forward credentials cross-origin."""

    def __init__(self, allow_private: bool = False):
        self.allow_private = bool(allow_private)

    @staticmethod
    def _origin(parsed):
        """Full origin, so a scheme or port change counts as cross-origin."""
        try:
            return (parsed.scheme.casefold(), (parsed.hostname or "").casefold(),
                    parsed.port or (443 if parsed.scheme.casefold() == "https" else 80))
        except ValueError:
            return None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.allow_private and not net_guard.is_public_url(newurl):
            raise urllib.error.HTTPError(newurl, 403, "redirect target is not public",
                                         headers, fp)
        try:
            old, target = urlsplit(req.full_url), urlsplit(str(newurl))
        except ValueError:
            old = target = None
        if old is not None and old.scheme.casefold() == "https" and target.scheme.casefold() == "http":
            # A bearer token must never be replayed in cleartext.
            raise urllib.error.HTTPError(newurl, 403, "refusing an https-to-http redirect",
                                         headers, fp)
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        try:
            old_origin = self._origin(old) if old is not None else None
            new_origin = self._origin(target) if target is not None else None
            if new is not None and (old_origin is None or old_origin != new_origin):
                for name in ("Authorization", "Cookie", "Proxy-Authorization"):
                    new.remove_header(name)
        except (ValueError, AttributeError):
            pass
        return new


_PinnedHTTPConnection = net_guard.PinnedHTTPConnection
_PinnedHTTPSConnection = net_guard.PinnedHTTPSConnection
_PinnedHTTPHandler = net_guard.PinnedHTTPHandler
_PinnedHTTPSHandler = net_guard.PinnedHTTPSHandler


class Http:
    """Small HTTP client; optional named credential is injected server-side."""

    def request(self, method: str, url: str, headers: dict | None = None,
                body: str | None = None, credential: str | None = None,
                timeout: int = 30, secrets: SecretStore | None = None,
                allow_private: bool = False) -> dict:
        method = str(method or "GET").upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
            raise ToolError("Unsupported HTTP method.")
        if not isinstance(url, str) or not re.match(r"^https?://", url, re.I) or len(url) > 2048:
            raise ToolError("An HTTP request needs an http(s) URL.")
        if not allow_private and not net_guard.is_public_url(url):
            raise ToolError("Refusing a non-public HTTP target.")
        if headers is not None and not isinstance(headers, dict):
            raise ToolError("HTTP headers must be an object.")
        out_headers = dict(list({
            str(key): str(value) for key, value in (headers or {}).items()
            if re.match(r"^[A-Za-z0-9-]{1,80}$", str(key))
        }.items())[:30])
        if credential:
            if secrets is None:
                raise ToolError("No credential store is available.")
            token = str(secrets.get(credential).get("value") or "")
            out_headers.setdefault("Authorization", f"Bearer {token}")
        else:
            token = ""
        data = body.encode("utf-8") if body is not None else None
        if data is not None and len(data) > 2_000_000:
            raise ToolError("HTTP body is too large.")
        request = urllib.request.Request(url, data=data, headers=out_headers, method=method)
        opener = urllib.request.build_opener(
            _PinnedHTTPHandler(allow_private), _PinnedHTTPSHandler(allow_private),
            _SafeRedirect(allow_private), urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=max(1, min(int(timeout or 30), 120))) as response:
                raw = response.read(1_000_000)
                status = response.status
                content_type = response.headers.get("Content-Type", "")
        except urllib.error.HTTPError as error:
            return {"ok": False, "status": error.code, "error": redact(str(error.reason), 500)}
        except Exception as error:
            raise ToolError(f"The HTTP request failed: {type(error).__name__}.") from None
        text = raw.decode("utf-8", errors="replace")
        if token:
            text = text.replace(token, "[REDACTED]")
        return {"ok": 200 <= status < 400, "status": status, "content_type": content_type,
                "body": redact(text, 12000), "truncated": len(raw) >= 1_000_000}

def _keyring_backend():
    try:
        import keyring
        backend = keyring.get_keyring()
        if backend is None or backend.__class__.__name__ in ("FailKeyring", "NoKeyringError"):
            return None
        return keyring
    except Exception:
        return None


class SecretStore:
    """A credential broker backed by the desktop keyring when available.

    The JSON file keeps only names/types for discovery; the value and TOTP seed
    live in SecretService. A temporary/test store keeps the old 0600 JSON form
    so unit tests never write to the user's real keyring.
    """

    SERVICE = "jarvis"
    _LOCK = threading.RLock()  # read-modify-write on the JSON metadata file

    def __init__(self, path: Path = SECRETS_PATH):
        self.path = path
        self.keyring = _keyring_backend() if path == SECRETS_PATH else None

    def _load(self) -> dict:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_payload(self, payload: dict, values: bool = False) -> None:
        """Write atomically; metadata-only mode strips the plaintext values."""
        metadata = {}
        if not values:
            for name, item in payload.items():
                if not isinstance(item, dict):
                    continue
                metadata[name] = {"type": item.get("type", "password")}
            payload = metadata
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(f".tmp-{int(time.time())}-{uuid.uuid4().hex[:6]}")
        temporary.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(self.path)

    def names(self) -> list[dict]:
        return [{"name": key, "type": value.get("type", "password")}
                for key, value in self._load().items() if isinstance(value, dict)]

    def get(self, name: str) -> dict:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name):
            raise ToolError("Invalid credential name.")
        if self.keyring:
            try:
                raw = self.keyring.get_password(self.SERVICE, name)
            except Exception as error:
                raise ToolError(f"The desktop keyring could not be read: {type(error).__name__}.") from None
            if raw:
                try:
                    item = json.loads(raw)
                except ValueError:
                    raise ToolError("The keyring entry is not valid JSON.") from None
                if isinstance(item, dict):
                    return item
        item = self._load().get(name)
        if not isinstance(item, dict):
            raise ToolError(f"No credential named {name!r} is stored.")
        if self.keyring and (item.get("value") or item.get("totp")):
            # One-time migration from the old plaintext store.
            self.put(name, item)
        return item

    def put(self, name: str, value: dict) -> None:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name):
            raise ToolError("Invalid credential name.")
        if not isinstance(value, dict) or not value:
            raise ToolError("A credential needs a value.")
        with SecretStore._LOCK:
            payload = self._load()
            if self.keyring:
                try:
                    self.keyring.set_password(self.SERVICE, name, json.dumps(value, ensure_ascii=True))
                except Exception as error:
                    raise ToolError(f"The desktop keyring is locked or unavailable: {type(error).__name__}.") from None
                payload[name] = {"type": value.get("type", "password")}
                self._save_payload(payload)
                return
            payload[name] = value
            self._save_payload(payload, values=True)

    def remove(self, name: str) -> None:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name):
            raise ToolError("Invalid credential name.")
        with SecretStore._LOCK:
            if self.keyring:
                try:
                    self.keyring.delete_password(self.SERVICE, name)
                except Exception as error:
                    # Removing the metadata while the keyring entry stays live
                    # would silently leave a working credential behind.
                    raise ToolError(f"The desktop keyring refused removal: "
                                    f"{type(error).__name__}.") from None
            payload = self._load()
            payload.pop(name, None)
            self._save_payload(payload, values=True)

    def totp(self, name: str, at: float | None = None) -> str:
        item = self.get(name)
        seed = str(item.get("totp") or item.get("secret") or "")
        if not seed:
            raise ToolError("That credential has no TOTP seed.")
        try:
            key = base64.b32decode(seed.upper().replace(" ", ""), casefold=True)
        except Exception:
            raise ToolError("The stored TOTP seed is not valid base32.") from None
        counter = int((time.time() if at is None else at)) // 30
        digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % 1_000_000
        return f"{code:06d}"


class Pty:
    """Interactive terminal sessions for sudo/ssh/npm login and REPLs."""

    ANSI = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]")

    def __init__(self, workspace: Path = HOME):
        self.workspace = workspace
        self.sessions: dict[str, dict] = {}

    def start(self, command: str = "exec /bin/bash -i", name: str | None = None,
              cwd: str | None = None) -> dict:
        if not isinstance(command, str) or not command.strip() or len(command) > 8000:
            raise ToolError("A PTY command must be non-empty text under 8,000 characters.")
        workdir = resolve_path(cwd or str(self.workspace), base=self.workspace, must_exist=True)
        label = str(name or f"pty-{uuid.uuid4().hex[:6]}")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", label):
            raise ToolError("Invalid PTY session name.")
        if label in self.sessions:
            raise ToolError("That PTY session name is already in use.")
        if len(self.sessions) >= 8:
            dead = [key for key, item in self.sessions.items()
                    if item["process"].poll() is not None]
            for key in dead:
                self.close(key)
            if len(self.sessions) >= 8:
                raise ToolError("Too many open PTY sessions; close an existing session first.")
        master, slave = pty.openpty()
        try:
            process = subprocess.Popen(
                ["/bin/bash", "-lc", command], cwd=str(workdir), stdin=slave,
                stdout=slave, stderr=slave, start_new_session=True,
                env={**os.environ, "PWD": str(workdir), "TERM": "xterm-256color"},
            )
        except BaseException:
            # A failed spawn must not leak the master descriptor: previous
            # behaviour closed only the slave side.
            os.close(master)
            raise
        finally:
            os.close(slave)
        self.sessions[label] = {"master": master, "process": process, "pid": process.pid,
                                "cwd": str(workdir), "buffer": ""}
        return {"ok": True, "session": label, "pid": process.pid, "cwd": str(workdir)}

    def _session(self, name: str) -> dict:
        if not isinstance(name, str) or name not in self.sessions:
            raise ToolError("That PTY session does not exist.")
        return self.sessions[name]

    def read(self, name: str, timeout: float = 0.8) -> dict:
        session = self._session(name)
        deadline = time.monotonic() + max(0.1, min(float(timeout or 0.8), 10.0))
        chunks = []
        while time.monotonic() < deadline:
            ready, _, _ = select.select([session["master"]], [], [], 0.1)
            if not ready:
                if session["process"].poll() is not None:
                    break
                continue
            try:
                chunk = os.read(session["master"], 65536)
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(part) for part in chunks) > 12000:
                break
        text = b"".join(chunks).decode("utf-8", errors="replace")
        text = self.ANSI.sub("", text)
        text = redact(text, 12000)
        return {"ok": True, "session": name, "output": text,
                "alive": session["process"].poll() is None,
                "exit_code": session["process"].poll()}

    def write(self, name: str, text: str, enter: bool = True) -> dict:
        session = self._session(name)
        if not isinstance(text, str) or len(text) > 8000:
            raise ToolError("PTY input must be text under 8,000 characters.")
        payload = text + ("\n" if enter else "")
        try:
            os.write(session["master"], payload.encode("utf-8"))
        except OSError as error:
            raise ToolError(f"The PTY input could not be written: {type(error).__name__}.") from None
        return {"ok": True, "session": name, "bytes": len(payload)}

    def close(self, name: str | None = None) -> dict:
        names = [name] if name else list(self.sessions)
        closed = []
        for label in names:
            session = self.sessions.pop(label, None)
            if not session:
                continue
            try:
                if session["process"].poll() is None:
                    os.killpg(session["process"].pid, 15)
            except OSError:
                pass
            try:
                session["process"].wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(session["process"].pid, 9)
                except OSError:
                    pass
                try:
                    session["process"].wait(timeout=2)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            try:
                os.close(session["master"])
            except OSError:
                pass
            closed.append(label)
        return {"ok": True, "closed": closed}
