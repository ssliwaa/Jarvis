"""Transparent filesystem checkpoints in a shared shadow git store.

The model never sees this module.  Before a file-mutating Operator action the
host records the working tree in a bare git repository under
``~/.jarvis-tools/checkpoints``.  One shared content-addressed object store is
used for every project; per-project refs, indexes and metadata live beside it.
The user's project gets no ``.git`` directory and no hooks.

Design adapted from Hermes Agent's ``tools/checkpoint_manager.py`` (MIT),
including its agent-write ledger and safe-restore rules.  Jarvis has one local
process and no Hermes gateway, so the persistence contract is the same but the
lock is a POSIX ``flock`` in :mod:`checkpoint_pruning`.

Storage layout::

    ~/.jarvis-tools/checkpoints/
        store/                       bare git repository
            objects/                 deduplicated blobs and trees
            refs/jarvis/<hash16>     per-project history
            indexes/<hash16>         per-project git index
            projects/<hash16>.json   workdir and timestamps
            ledgers/<hash16>.json    hashes of files Jarvis wrote
            info/exclude             secrets/build/media exclusions
        .checkpoints.lock            process/thread lock (beside base)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path, PurePosixPath
from typing import Any

from checkpoint_pruning import PruneError, Pruner, store_lock

logger = logging.getLogger("jarvis.checkpoints")

DEFAULT_BASE = Path.home() / ".jarvis-tools" / "checkpoints"
_STORE_DIRNAME = "store"
_REFS_PREFIX = "refs/jarvis"
_INDEXES_DIRNAME = "indexes"
_PROJECTS_DIRNAME = "projects"
_LEDGERS_DIRNAME = "ledgers"
_PRUNE_MARKER_NAME = ".last_prune"
_LEDGER_MAX_ENTRIES = 4000
_GIT_TIMEOUT = 30
_MAX_FILES = 50_000
_COMMIT_HASH_RE = re.compile(r"^[0-9a-fA-F]{4,64}$")

DEFAULT_EXCLUDES = [
    # dependency and build output
    "node_modules/",
    "dist/",
    "build/",
    "target/",
    "out/",
    ".next/",
    ".nuxt/",
    "__pycache__/",
    "*.pyc",
    "*.pyo",
    ".cache/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    "coverage/",
    ".coverage",
    # virtualenvs
    ".venv/",
    "venv/",
    "env/",
    # VCS metadata
    ".git/",
    ".jarvis-tools/",
    ".hermes/",
    ".hg/",
    ".svn/",
    # local build artifacts
    "artifacts/",
    "desktop/node_modules/",
    # native / compiled / media
    "*.so",
    "*.dylib",
    "*.dll",
    "*.o",
    "*.a",
    "*.jar",
    "*.class",
    "*.exe",
    "*.obj",
    "*.mp4",
    "*.mov",
    "*.mkv",
    "*.webm",
    "*.zip",
    "*.tar",
    "*.tar.gz",
    "*.tgz",
    "*.7z",
    "*.rar",
    "*.iso",
    "*.db",
    "*.db-wal",
    "*.db-shm",
    "*.sqlite",
    "*.sqlite3",
    # secrets and credentials
    ".env",
    ".env.*",
    ".env.local",
    ".env.*.local",
    ".ssh/",
    ".gnupg/",
    ".aws/",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
    "secrets.json",
    "auth.json",
    "config.json",
    "config.local.json",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_ed25519",
    # OS junk
    ".DS_Store",
    "Thumbs.db",
    # logs
    "*.log",
]


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _normalize(path_value: str | Path) -> Path:
    return Path(path_value).expanduser().resolve()


def _project_hash(working_dir: str | Path) -> str:
    return hashlib.sha256(str(_normalize(working_dir)).encode()).hexdigest()[:16]


def _ref_name(dir_hash: str) -> str:
    return f"{_REFS_PREFIX}/{dir_hash}"


def _gitlink_paths(ls_tree_z: str) -> list[str]:
    return [
        record.split("\t", 1)[1]
        for record in ls_tree_z.split("\x00")
        if record.startswith("160000 commit ") and "\t" in record
    ]


def _git_env(store: Path, working_dir: str | Path, index_file: Path | None = None) -> dict[str, str]:
    """Isolate git from the user's config while redirecting it to the store."""
    env = dict(os.environ)
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_NAMESPACE",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        env.pop(key, None)
    env["GIT_DIR"] = str(store)
    env["GIT_WORK_TREE"] = str(_normalize(working_dir))
    if index_file is not None:
        env["GIT_INDEX_FILE"] = str(index_file)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_ATTR_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _run_git(
    args: list[str],
    store: Path,
    working_dir: str | Path,
    timeout: int = _GIT_TIMEOUT,
    allowed_returncodes: set[int] | None = None,
    index_file: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> tuple[bool, str, str]:
    workdir = _normalize(working_dir)
    if not workdir.exists():
        return False, "", f"working directory not found: {workdir}"
    if not workdir.is_dir():
        return False, "", f"working directory is not a directory: {workdir}"
    env = _git_env(store, workdir, index_file)
    if extra_env:
        env.update(extra_env)
    git = shutil.which("git", path=env.get("PATH", ""))
    if git is None:
        return False, "", "git is not installed or not on PATH"
    command = [git, *args]
    allowed = allowed_returncodes or set()
    try:
        if "-z" in args:
            result = subprocess.run(
                command, capture_output=True, timeout=timeout, env=env,
                cwd=str(workdir), stdin=subprocess.DEVNULL, check=False,
            )
            stdout = os.fsdecode(result.stdout)
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
        else:
            result = subprocess.run(
                command, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout, env=env, cwd=str(workdir),
                stdin=subprocess.DEVNULL, check=False,
            )
            stdout, stderr = result.stdout.strip(), result.stderr.strip()
        ok = result.returncode == 0
        if not ok and result.returncode not in allowed:
            logger.debug("git failed rc=%s: %s", result.returncode, " ".join(command))
        return ok, stdout, stderr
    except subprocess.TimeoutExpired:
        return False, "", f"git timed out after {timeout}s"
    except OSError as error:
        return False, "", f"{type(error).__name__}: {error}"


def _git_out(args: list[str], store: Path, working_dir: str | Path, rc: set[int] | None = None) -> str:
    ok, out, _ = _run_git(args, store, working_dir, allowed_returncodes=rc)
    return out if ok else ""


def _ledger_path(store: Path, dir_hash: str) -> Path:
    return store / _LEDGERS_DIRNAME / f"{dir_hash}.json"


def _index_path(store: Path, dir_hash: str) -> Path:
    return store / _INDEXES_DIRNAME / dir_hash


def _project_meta_path(store: Path, dir_hash: str) -> Path:
    return store / _PROJECTS_DIRNAME / f"{dir_hash}.json"


def _hash_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _load_ledger(store: Path, dir_hash: str) -> dict[str, dict]:
    try:
        raw = _ledger_path(store, dir_hash).read_text(encoding="utf-8-sig")
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, UnicodeError):
        return {}


def _save_ledger(store: Path, dir_hash: str, ledger: dict[str, dict]) -> None:
    try:
        if len(ledger) > _LEDGER_MAX_ENTRIES:
            newest = sorted(
                ledger.items(),
                key=lambda item: item[1].get("ts", 0) if isinstance(item[1], dict) else 0,
                reverse=True,
            )[:_LEDGER_MAX_ENTRIES]
            ledger = dict(newest)
        path = _ledger_path(store, dir_hash)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(ledger, ensure_ascii=True), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(path)
    except OSError:
        logger.debug("could not save checkpoint ledger for %s", dir_hash, exc_info=True)


def _dir_size_bytes(path: Path) -> int:
    total = 0
    try:
        for root, _dirs, files in os.walk(path, followlinks=False):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(root, name))
                except OSError:
                    continue
    except OSError:
        pass
    return total


def _dir_file_count(path: Path, limit: int) -> int:
    count = 0
    try:
        for _root, _dirs, files in os.walk(path, followlinks=False):
            count += len(files)
            if count > limit:
                return count
    except OSError:
        pass
    return count


_ALWAYS_PRIVATE_PARTS = {
    ".ssh", ".gnupg", ".aws", ".env", ".venv", "venv", "node_modules",
    ".git", ".hg", ".svn", "__pycache__", ".jarvis-tools", ".hermes",
}
_ALWAYS_PRIVATE_NAMES = {
    ".env", ".netrc", ".npmrc", ".pypirc", "credentials", "secrets.json",
    "auth.json", "config.json", "config.local.json", "id_rsa", "id_ed25519",
}


def _is_private_relative(relative: str) -> bool:
    """True for paths that must never enter the shadow object store.

    ``info/exclude`` is normally enough, but a project's ``.gitignore`` can
    re-include an excluded path with a negation.  This post-stage predicate
    is the enforcement point, not just a default.
    """
    path = PurePosixPath(relative)
    if any(part in _ALWAYS_PRIVATE_PARTS for part in path.parts):
        return True
    if path.name in _ALWAYS_PRIVATE_NAMES or path.name.startswith(".env."):
        return True
    return path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}


def _volume_evidence(workdir: Path) -> dict:
    """Record parent-directory identity while the project is reachable."""
    try:
        if not workdir.exists():
            return {}
        stat_result = workdir.parent.stat()
        if not stat_result.st_dev or not stat_result.st_ino:
            return {}
        return {"workdir_parent_dev": stat_result.st_dev,
                "workdir_parent_ino": stat_result.st_ino}
    except OSError:
        return {}


def _register_project(store: Path, working_dir: str) -> None:
    path = _project_meta_path(store, _project_hash(working_dir))
    now = time.time()
    meta: dict[str, Any] = {
        "workdir": str(_normalize(working_dir)),
        "created_at": now,
        "last_touch": now,
    }
    meta.update(_volume_evidence(_normalize(working_dir)))
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8-sig"))
            if isinstance(existing, dict):
                meta["created_at"] = existing.get("created_at", now)
                for key in ("workdir_parent_dev", "workdir_parent_ino"):
                    if key not in meta and key in existing:
                        meta[key] = existing[key]
        except (OSError, ValueError):
            pass
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(meta), encoding="utf-8")
    except OSError:
        logger.debug("could not write checkpoint project metadata", exc_info=True)


def _touch_project(store: Path, working_dir: str) -> None:
    path = _project_meta_path(store, _project_hash(working_dir))
    _register_project(store, working_dir) if not path.exists() else None
    if not path.exists():
        return
    try:
        meta = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    meta["workdir"] = str(_normalize(working_dir))
    meta["last_touch"] = time.time()
    meta.setdefault("created_at", meta["last_touch"])
    meta.update(_volume_evidence(_normalize(working_dir)))
    try:
        path.write_text(json.dumps(meta), encoding="utf-8")
    except OSError:
        pass


def _list_projects(store: Path) -> list[dict]:
    root = store / _PROJECTS_DIRNAME
    if not root.is_dir():
        return []
    projects = []
    for meta_path in root.glob("*.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        if isinstance(meta, dict):
            meta["_hash"] = meta_path.stem
            projects.append(meta)
    return projects


def _init_store(base: Path) -> str | None:
    store = base / _STORE_DIRNAME
    try:
        base.mkdir(parents=True, exist_ok=True)
        base.chmod(0o700)
    except OSError as error:
        return f"could not create checkpoint base: {error}"
    if (store / "HEAD").exists():
        return None
    store.mkdir(parents=True, exist_ok=True)
    try:
        store.chmod(0o700)
    except OSError:
        pass
    (store / _INDEXES_DIRNAME).mkdir(exist_ok=True)
    (store / _PROJECTS_DIRNAME).mkdir(exist_ok=True)
    (store / _LEDGERS_DIRNAME).mkdir(exist_ok=True)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("GIT_")}
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    git = shutil.which("git", path=env.get("PATH", ""))
    if git is None:
        return "git is not installed or not on PATH"
    try:
        result = subprocess.run(
            [git, "init", "--bare", str(store)], capture_output=True, text=True,
            encoding="utf-8", errors="replace", env=env, timeout=_GIT_TIMEOUT,
            stdin=subprocess.DEVNULL, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"shadow store init failed: {error}"
    if result.returncode != 0:
        return f"shadow store init failed: {result.stderr.strip()}"
    config = base
    for key, value in (
        ("user.email", "jarvis@local"),
        ("user.name", "Jarvis Checkpoint"),
        ("commit.gpgsign", "false"),
        ("tag.gpgSign", "false"),
        ("gc.auto", "0"),
        ("core.autocrlf", "false"),
    ):
        _run_git(["config", key, value], store, config)
    info = store / "info"
    info.mkdir(exist_ok=True)
    (info / "exclude").write_text("\n".join(DEFAULT_EXCLUDES) + "\n", encoding="utf-8")
    return None


class CheckpointError(Exception):
    pass


class CheckpointManager:
    """Automatic, deduplicated filesystem snapshots plus rollback.

    ``enabled`` is the master switch.  ``ensure_checkpoint`` is safe to call
    before every mutating tool: it skips a directory already snapshotted in
    the current turn, skips root/home, and never raises into the tool path.
    """

    def __init__(
        self,
        *,
        base: Path | str | None = None,
        enabled: bool | None = None,
        max_snapshots: int | None = None,
        max_total_size_mb: int | None = None,
        max_file_size_mb: int | None = None,
        max_files: int | None = None,
        git_timeout: int | None = None,
    ):
        env_base = os.environ.get("JARVIS_CHECKPOINT_BASE", "").strip()
        self.base = _normalize(base or env_base or DEFAULT_BASE)
        self.enabled = (os.environ.get("JARVIS_CHECKPOINTS", "1") != "0"
                        if enabled is None else bool(enabled))
        self.max_snapshots = max(1, int(
            max_snapshots if max_snapshots is not None
            else _env_int("JARVIS_CHECKPOINT_MAX_SNAPSHOTS", 20)
        ))
        self.max_total_size_mb = max(0, int(
            max_total_size_mb if max_total_size_mb is not None
            else _env_int("JARVIS_CHECKPOINT_MAX_TOTAL_MB", 500)
        ))
        self.max_file_size_mb = max(0, int(
            max_file_size_mb if max_file_size_mb is not None
            else _env_int("JARVIS_CHECKPOINT_MAX_FILE_MB", 10)
        ))
        self.max_files = max(100, int(
            max_files if max_files is not None
            else _env_int("JARVIS_CHECKPOINT_MAX_FILES", _MAX_FILES)
        ))
        self.git_timeout = max(5, int(
            git_timeout if git_timeout is not None
            else _env_int("JARVIS_CHECKPOINT_TIMEOUT", _GIT_TIMEOUT)
        ))
        self._checkpointed_dirs: set[str] = set()

    # -- store paths ------------------------------------------------------

    @property
    def store(self) -> Path:
        return self.base / _STORE_DIRNAME

    @staticmethod
    def _validate_hash(value: str) -> str | None:
        if not value or not str(value).strip():
            return "Empty commit hash."
        value = str(value).strip()
        if value.startswith("-"):
            return "Invalid commit hash."
        if not _COMMIT_HASH_RE.fullmatch(value):
            return "Invalid commit hash (expected 4-64 hex characters)."
        return None

    @staticmethod
    def _validate_file_path(file_path: str, working_dir: str | Path) -> str | None:
        if not file_path or not str(file_path).strip():
            return "Empty file path."
        if os.path.isabs(file_path):
            return "File path must be relative."
        root = _normalize(working_dir)
        try:
            (_normalize(root / file_path)).relative_to(root)
        except ValueError:
            return "File path escapes the working directory."
        return None

    # -- turn lifecycle ---------------------------------------------------

    def new_turn(self) -> None:
        """Reset per-turn deduplication; call once per model step."""
        self._checkpointed_dirs.clear()

    def ensure_checkpoint(self, working_dir: str | Path, reason: str = "auto") -> bool:
        """Snapshot ``working_dir`` once per turn; never raises."""
        if not self.enabled:
            return False
        try:
            root = _normalize(working_dir)
        except (OSError, ValueError):
            return False
        broad = {
            Path("/"), Path.home(), Path("/home"), Path("/tmp"), Path("/var/tmp"),
            Path.home() / ".jarvis-tools", Path.home() / ".hermes",
        }
        if root in broad:
            return False
        key = str(root)
        if key in self._checkpointed_dirs:
            return False
        self._checkpointed_dirs.add(key)
        try:
            with store_lock(self.base):
                return self._take(str(root), reason)
        except Exception:
            logger.debug("checkpoint skipped for %s", root, exc_info=True)
            return False

    # -- agent write ledger ----------------------------------------------

    def record_agent_write(self, file_path: str) -> None:
        """Record the hash of a file Jarvis just wrote (safe restore input)."""
        if not self.enabled:
            return
        try:
            path = _normalize(file_path)
            digest = _hash_file(path)
            if digest is None:
                return
            with store_lock(self.base):
                dir_hash = self._ledger_key(str(path))
                ledger = _load_ledger(self.store, dir_hash)
                ledger[str(path)] = {"sha256": digest, "ts": time.time()}
                _save_ledger(self.store, dir_hash, ledger)
        except Exception:
            logger.debug("agent-write ledger update failed for %s", file_path, exc_info=True)

    def _ledger_key(self, path: str) -> str:
        return _project_hash(self.get_working_dir_for_path(path))

    # -- project discovery -----------------------------------------------

    def get_working_dir_for_path(self, file_path: str) -> str:
        """Resolve a file path to the project directory that owns it."""
        path = _normalize(file_path)
        candidate = path if path.is_dir() else path.parent
        # A write may target a directory that does not exist yet. Walk up to
        # the nearest existing ancestor so project markers can still be found.
        while not candidate.exists() and candidate != candidate.parent:
            candidate = candidate.parent
        roots = [Path(meta["workdir"]) for meta in _list_projects(self.store)
                 if isinstance(meta.get("workdir"), str)]
        owners = [root for root in roots if candidate.is_relative_to(root)]
        if owners:
            return str(max(owners, key=lambda root: len(root.parts)))
        markers = {".git", "pyproject.toml", "package.json", "Cargo.toml",
                   "go.mod", "Makefile", "pom.xml", ".hg", "Gemfile"}
        home = Path.home().resolve()
        broad = {home, *home.parents}
        check = candidate
        while check != check.parent and check not in broad:
            if any((check / marker).exists() for marker in markers):
                return str(check)
            check = check.parent
        return str(candidate)

    # -- listing / diff ---------------------------------------------------

    def list_checkpoints(self, working_dir: str | Path) -> list[dict]:
        if not self.enabled:
            return []
        root = str(_normalize(working_dir))
        if not (self.store / "HEAD").exists():
            return []
        ref = _ref_name(_project_hash(root))
        with store_lock(self.base):
            ok, stdout, _ = _run_git(
                ["log", ref, "--format=%H|%h|%aI|%s", "-n", str(self.max_snapshots)],
                self.store, root, allowed_returncodes={128, 129},
            )
        if not ok or not stdout:
            return []
        entries = []
        for line in stdout.splitlines():
            parts = line.split("|", 3)
            if len(parts) != 4:
                continue
            entry = {"hash": parts[0], "short_hash": parts[1],
                     "timestamp": parts[2], "reason": parts[3],
                     "files_changed": 0, "insertions": 0, "deletions": 0}
            with store_lock(self.base):
                stat_ok, stat_out, _ = _run_git(
                    ["diff", "--shortstat", f"{parts[0]}~1", parts[0]],
                    self.store, root, allowed_returncodes={128, 129},
                )
            if stat_ok and stat_out:
                self._parse_shortstat(stat_out, entry)
            entries.append(entry)
        return entries

    def list_all_checkpoints(self) -> list[dict]:
        if not self.enabled or not (self.store / "HEAD").exists():
            return []
        entries = []
        for meta in _list_projects(self.store):
            workdir = meta.get("workdir") or ""
            if not workdir:
                continue
            for entry in self.list_checkpoints(workdir):
                entry["workdir"] = workdir
                entries.append(entry)
        entries.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
        return entries

    @staticmethod
    def _parse_shortstat(line: str, entry: dict) -> None:
        for key, pattern in (
            ("files_changed", r"(\d+) file"),
            ("insertions", r"(\d+) insertion"),
            ("deletions", r"(\d+) deletion"),
        ):
            match = re.search(pattern, line)
            if match:
                entry[key] = int(match.group(1))

    def diff(self, working_dir: str | Path, commit_hash: str) -> dict:
        if not self.enabled:
            return {"success": False, "error": "Checkpoints are disabled."}
        error = self._validate_hash(commit_hash)
        if error:
            return {"success": False, "error": error}
        root = str(_normalize(working_dir))
        if not (self.store / "HEAD").exists():
            return {"success": False, "error": "No checkpoints exist for this directory."}
        with store_lock(self.base):
            return self._diff(root, commit_hash)

    def _diff(self, root: str, commit_hash: str) -> dict:
        ok, _, _ = _run_git(["cat-file", "-t", commit_hash], self.store, root)
        if not ok:
            return {"success": False, "error": f"Checkpoint '{commit_hash}' not found."}
        dir_hash = _project_hash(root)
        index_file = _index_path(self.store, dir_hash)
        _run_git(["add", "-A"], self.store, root, timeout=self.git_timeout * 2,
                 index_file=index_file)
        self._drop_private_from_index(root, index_file)
        ok_stat, stat_out, _ = _run_git(
            ["diff", "--stat", commit_hash, "--cached"], self.store, root,
            index_file=index_file,
        )
        ok_diff, diff_out, _ = _run_git(
            ["diff", commit_hash, "--cached", "--no-color"], self.store, root,
            index_file=index_file,
        )
        _run_git(["read-tree", _ref_name(dir_hash)], self.store, root,
                 index_file=index_file, allowed_returncodes={128})
        if not ok_stat and not ok_diff:
            return {"success": False, "error": "Could not generate diff."}
        return {"success": True, "stat": stat_out if ok_stat else "",
                "diff": diff_out if ok_diff else ""}

    def session_diff(self, working_dir: str | Path) -> dict:
        checkpoints = self.list_checkpoints(working_dir)
        if not checkpoints:
            return {"success": True, "stat": "", "diff": "", "empty": True}
        result = self.diff(working_dir, checkpoints[-1]["hash"])
        if result.get("success"):
            result.setdefault("baseline", checkpoints[-1]["hash"])
            if not result.get("stat") and not result.get("diff"):
                result["empty"] = True
        return result

    # -- restore ----------------------------------------------------------

    def restore(
        self,
        working_dir: str | Path,
        commit_hash: str,
        file_path: str | None = None,
        safe: bool = False,
    ) -> dict:
        """Restore a directory or one file to a checkpoint.

        ``safe=True`` keeps files whose current content no longer matches the
        agent-write ledger (i.e. the user hand-edited them) and refuses to
        delete a path that is over the snapshot size cap.  ``safe=False`` is
        a full rollback: files created after the checkpoint are removed, so
        the working tree returns to the recorded state.
        """
        if not self.enabled:
            return {"success": False, "error": "Checkpoints are disabled."}
        error = self._validate_hash(commit_hash)
        if error:
            return {"success": False, "error": error}
        root = str(_normalize(working_dir))
        if file_path:
            path_error = self._validate_file_path(file_path, root)
            if path_error:
                return {"success": False, "error": path_error}
        if not (self.store / "HEAD").exists():
            return {"success": False, "error": "No checkpoints exist for this directory."}
        try:
            with store_lock(self.base):
                return self._restore(root, commit_hash, file_path, bool(safe))
        except (PruneError, OSError) as error:
            return {"success": False, "error": str(error)}

    def _restore(self, root: str, commit_hash: str, file_path: str | None, safe: bool) -> dict:
        ok, _, _ = _run_git(["cat-file", "-t", commit_hash], self.store, root)
        if not ok:
            return {"success": False, "error": f"Checkpoint '{commit_hash}' not found."}
        ok, tree_out, _ = _run_git(["ls-tree", "-r", "-z", commit_hash], self.store, root)
        if not ok:
            return {"success": False, "error": "Could not inspect checkpoint."}
        nested = _gitlink_paths(tree_out)
        if nested:
            if file_path:
                parts = PurePosixPath(file_path).parts
                for repo in nested:
                    repo_parts = PurePosixPath(repo).parts
                    if parts[:len(repo_parts)] == repo_parts:
                        return {"success": False,
                                "error": f"File is inside an uncaptured nested git repository: {repo}"}
            else:
                return {"success": False,
                        "error": "Checkpoint contains nested git repositories that were not captured: "
                                 + ", ".join(nested)}
        # Snapshot the current state first, so a rollback can itself be undone.
        self._take(root, f"pre-rollback snapshot (restoring to {commit_hash[:8]})", prune=False)
        index_file = _index_path(self.store, _project_hash(root))

        if file_path:
            ok, _, error = _run_git(
                ["checkout", commit_hash, "--", file_path], self.store, root,
                timeout=self.git_timeout * 2, index_file=index_file,
            )
            if not ok:
                return {"success": False, "error": f"Restore failed: {error}"}
            return {"success": True, "restored_to": commit_hash[:8],
                    "directory": root, "file": file_path}

        current_paths = self._staged_paths(root)
        checkpoint_paths = set(
            filter(None, _git_out(["ls-tree", "-r", "--name-only", "-z", commit_hash],
                                  self.store, root).split("\x00"))
        )
        extra_paths = current_paths - checkpoint_paths
        restore_paths: set[str] | None = None
        skipped_user_edits: list[str] = []
        skipped_oversize: list[str] = []
        if safe:
            plan = self._safe_restore_plan(root, commit_hash)
            if not plan.get("success"):
                return {"success": False, "error": plan.get("error", "Safe restore plan failed.")}
            if plan.get("ledger_empty"):
                # Without an agent-write ledger there is no way to tell an
                # agent-created file from a user draft. Safe mode must not
                # guess; the caller can request an explicit full restore.
                return {
                    "success": False,
                    "error": "No agent-write history for this project; "
                             "use safe=false for an explicit full restore.",
                    "ledger_empty": True,
                }
            restore_paths = set(plan["restore"])
            skipped_user_edits = plan["skipped"]
            if not restore_paths:
                return {
                    "success": True, "restored_to": commit_hash[:8],
                    "reason": "nothing to restore (all changed files were user-edited)",
                    "directory": root, "restored_files": [],
                    "skipped_user_edits": skipped_user_edits,
                    "skipped_oversize": [],
                }
        if safe and restore_paths is not None:
            checkout_targets = sorted(restore_paths & checkpoint_paths)
            if checkout_targets:
                ok, _, error = _run_git(
                    ["checkout", commit_hash, "--", *checkout_targets], self.store, root,
                    timeout=self.git_timeout * 2, index_file=index_file,
                )
                if not ok:
                    return {"success": False, "error": f"Restore failed: {error}"}
        else:
            ok, _, error = _run_git(
                ["checkout", commit_hash, "--", "."], self.store, root,
                timeout=self.git_timeout * 2, index_file=index_file,
            )
            if not ok:
                return {"success": False, "error": f"Restore failed: {error}"}
        deleted: list[str] = []
        failed_deletes: list[str] = []
        candidates = extra_paths if restore_paths is None else (extra_paths & restore_paths)
        for relative in sorted(candidates):
            target = Path(root) / relative
            if self._exceeds_size_cap(target):
                skipped_oversize.append(relative)
                continue
            if safe and not self._ledger_owns(root, relative):
                skipped_user_edits.append(relative)
                continue
            try:
                if target.is_file() or target.is_symlink():
                    target.unlink()
                    deleted.append(relative)
                elif target.is_dir() and not target.is_symlink():
                    # Only remove an empty directory left behind by a deleted
                    # file; never recursively delete a real tree.
                    try:
                        target.rmdir()
                    except OSError:
                        pass
            except OSError:
                failed_deletes.append(relative)
        reason = _git_out(["log", "--format=%s", "-1", commit_hash], self.store, root) or "unknown"
        restored_now = (checkpoint_paths & current_paths) if restore_paths is None else (
            restore_paths & checkpoint_paths)
        result = {
            "success": True,
            "restored_to": commit_hash[:8],
            "reason": reason,
            "directory": root,
            "restored_files": sorted(restored_now),
            "deleted_files": deleted,
        }
        if safe:
            result["skipped_user_edits"] = skipped_user_edits
            result["skipped_oversize"] = skipped_oversize
            if failed_deletes:
                result["failed_deletes"] = failed_deletes
        try:
            self._prune(self.store, root, _ref_name(_project_hash(root)))
        except Exception:
            pass
        return result

    def _staged_paths(self, root: str) -> set[str]:
        dir_hash = _project_hash(root)
        index_file = _index_path(self.store, dir_hash)
        _run_git(["add", "-A"], self.store, root, timeout=self.git_timeout * 2,
                 index_file=index_file)
        self._drop_private_from_index(root, index_file)
        ok, output, _ = _run_git(["ls-files", "--cached", "-z"], self.store, root,
                                  index_file=index_file)
        _run_git(["read-tree", _ref_name(dir_hash)], self.store, root,
                 index_file=index_file, allowed_returncodes={128})
        return set(filter(None, output.split("\x00"))) if ok else set()

    def _ledger_owns(self, root: str, relative: str) -> bool:
        ledger = _load_ledger(self.store, self._ledger_key(str(Path(root) / relative)))
        entry = ledger.get(str(Path(root) / relative))
        return isinstance(entry, dict) and bool(entry.get("sha256"))

    def _safe_restore_plan(self, root: str, commit_hash: str) -> dict:
        dir_hash = _project_hash(root)
        index_file = _index_path(self.store, dir_hash)
        _run_git(["add", "-A"], self.store, root, timeout=self.git_timeout * 2,
                 index_file=index_file)
        self._drop_private_from_index(root, index_file)
        ok, names, error = _run_git(
            ["diff", "--name-only", "-z", commit_hash, "--cached"],
            self.store, root, index_file=index_file,
        )
        _run_git(["read-tree", _ref_name(dir_hash)], self.store, root,
                 index_file=index_file, allowed_returncodes={128})
        if not ok:
            return {"success": False, "error": f"Could not compute changed files: {error}"}
        ledger = _load_ledger(self.store, self._ledger_key(root))
        if not ledger:
            return {"success": True, "restore": [], "skipped": [], "ledger_empty": True}
        restore: list[str] = []
        skipped: list[str] = []
        for relative in filter(None, names.split("\x00")):
            absolute = str(Path(root) / relative)
            entry = ledger.get(absolute)
            recorded = entry.get("sha256") if isinstance(entry, dict) else None
            if recorded is None:
                skipped.append(relative)
                continue
            current = _hash_file(Path(absolute))
            if current is None or current == recorded:
                restore.append(relative)
            else:
                skipped.append(relative)
        return {"success": True, "restore": restore, "skipped": skipped}

    def _exceeds_size_cap(self, path: Path) -> bool:
        cap = self.max_file_size_mb * 1024 * 1024
        if cap <= 0:
            return False
        try:
            return path.stat().st_size > cap
        except OSError:
            return False

    # -- taking a snapshot ------------------------------------------------

    def _take(self, working_dir: str, reason: str, *, prune: bool = True) -> bool:
        error = _init_store(self.base)
        if error:
            logger.debug("checkpoint store init failed: %s", error)
            return False
        _touch_project(self.store, working_dir)
        if _dir_file_count(Path(working_dir), self.max_files) > self.max_files:
            logger.debug("checkpoint skipped: too many files in %s", working_dir)
            return False
        dir_hash = _project_hash(working_dir)
        index_file = _index_path(self.store, dir_hash)
        ref = _ref_name(dir_hash)
        if index_file.exists():
            ok_ref, ref_commit, _ = _run_git(
                ["rev-parse", "--verify", ref + "^{commit}"], self.store, working_dir,
                allowed_returncodes={128},
            )
            if ok_ref and ref_commit:
                _run_git(["read-tree", ref_commit], self.store, working_dir,
                         index_file=index_file, allowed_returncodes={128})
            else:
                try:
                    index_file.unlink()
                except OSError:
                    pass
        else:
            index_file.parent.mkdir(parents=True, exist_ok=True)
        ok, _, error = _run_git(
            ["add", "-A"], self.store, working_dir,
            timeout=self.git_timeout * 2, index_file=index_file,
        )
        if not ok:
            logger.debug("checkpoint git-add failed: %s", error)
            return False
        self._drop_private_from_index(working_dir, index_file)
        self._drop_oversize_from_index(working_dir, index_file)
        ok_ref, ref_commit, _ = _run_git(
            ["rev-parse", "--verify", ref + "^{commit}"], self.store, working_dir,
            allowed_returncodes={128},
        )
        has_ref = bool(ok_ref and ref_commit)
        if has_ref:
            ok_diff, _, _ = _run_git(
                ["diff-index", "--cached", "--quiet", ref_commit], self.store, working_dir,
                allowed_returncodes={1}, index_file=index_file,
            )
            if ok_diff:
                return False
        else:
            ok_ls, files, _ = _run_git(
                ["ls-files", "--cached"], self.store, working_dir, index_file=index_file)
            if ok_ls and not files.strip():
                return False
        ok, tree_sha, error = _run_git(
            ["write-tree"], self.store, working_dir, index_file=index_file)
        if not ok or not tree_sha:
            logger.debug("checkpoint write-tree failed: %s", error)
            return False
        ok_ls, tree_out, _ = _run_git(["ls-tree", "-r", "-z", tree_sha], self.store, working_dir)
        nested = _gitlink_paths(tree_out) if ok_ls else []
        if nested:
            reason = " ".join(line.strip() for line in reason.splitlines() if line.strip())
            reason += f" [nested git repos not captured: {', '.join(nested[:3])}]"
        args = ["commit-tree", tree_sha, "-m", reason[:4000], "--no-gpg-sign"]
        if has_ref:
            args += ["-p", ref_commit]
        ok, new_sha, error = _run_git(args, self.store, working_dir, index_file=index_file)
        if not ok or not new_sha:
            logger.debug("checkpoint commit-tree failed: %s", error)
            return False
        update = ["update-ref", ref, new_sha]
        if has_ref:
            update.append(ref_commit)
        ok, _, error = _run_git(update, self.store, working_dir)
        if not ok:
            logger.debug("checkpoint update-ref failed: %s", error)
            return False
        if prune:
            self._prune(self.store, working_dir, ref)
        return True

    def _drop_private_from_index(self, working_dir: str, index_file: Path) -> None:
        """Remove secret/state paths even if a project .gitignore re-included them."""
        ok, stdout, _ = _run_git(["ls-files", "--cached", "-z"], self.store,
                                 working_dir, index_file=index_file)
        if not ok or not stdout:
            return
        private = [path for path in stdout.split("\x00") if path and _is_private_relative(path)]
        for index in range(0, len(private), 200):
            chunk = private[index:index + 200]
            _run_git(["rm", "--cached", "--quiet", "--", *chunk], self.store,
                     working_dir, index_file=index_file, allowed_returncodes={128})

    def _drop_oversize_from_index(self, working_dir: str, index_file: Path) -> None:
        if self.max_file_size_mb <= 0:
            return
        ok, stdout, _ = _run_git(["ls-files", "--cached", "-z"], self.store,
                                 working_dir, index_file=index_file)
        if not ok or not stdout:
            return
        root = _normalize(working_dir)
        oversize = [path for path in stdout.split("\x00") if path
                    and self._exceeds_size_cap(root / path)]
        for index in range(0, len(oversize), 200):
            chunk = oversize[index:index + 200]
            _run_git(["rm", "--cached", "--quiet", "--", *chunk], self.store,
                     working_dir, index_file=index_file, allowed_returncodes={128})

    def _prune(self, store: Path, working_dir: str, ref: str) -> None:
        pruner = Pruner(_run_git, store, working_dir, self.git_timeout,
                        _dir_size_bytes, _REFS_PREFIX)
        try:
            pruner.trim(ref, self.max_snapshots)
            if pruner.drop_one_round(self.max_total_size_mb * 1024 * 1024):
                logger.info("checkpoint store over %s MB; oldest snapshot per project dropped",
                            self.max_total_size_mb)
        except (PruneError, OSError) as error:
            logger.warning("checkpoint pruning stopped: %s", error)

    # -- public maintenance ----------------------------------------------

    def status(self) -> dict:
        from checkpoint_maintenance import store_status
        return store_status(self.base)

    def prune(
        self,
        retention_days: int = 30,
        delete_orphans: bool = False,
        max_total_size_mb: int | None = None,
    ) -> dict:
        from checkpoint_maintenance import prune_checkpoints
        return prune_checkpoints(
            retention_days=max(0, int(retention_days)),
            delete_orphans=bool(delete_orphans),
            checkpoint_base=self.base,
            max_total_size_mb=(self.max_total_size_mb if max_total_size_mb is None
                               else int(max_total_size_mb)),
        )


def format_checkpoint_list(checkpoints: list[dict], directory: str = "") -> str:
    if not checkpoints:
        return f"No checkpoints found for {directory or 'this directory'}"
    lines = [f"Checkpoints for {directory or 'all directories'}:"]
    for index, checkpoint in enumerate(checkpoints, 1):
        timestamp = str(checkpoint.get("timestamp", ""))
        if "T" in timestamp:
            timestamp = timestamp.replace("T", " ").split("+")[0][:16]
        stats = ""
        if checkpoint.get("files_changed"):
            stats = (f" ({checkpoint['files_changed']} file(s), "
                     f"+{checkpoint.get('insertions', 0)}/-{checkpoint.get('deletions', 0)})")
        workdir = checkpoint.get("workdir")
        suffix = f" [{Path(workdir).name}]" if workdir and not directory else ""
        lines.append(f"{index}. {checkpoint.get('short_hash', '?')}  {timestamp}  "
                     f"{checkpoint.get('reason', '')}{suffix}{stats}")
    return "\n".join(lines)


def default_manager(*, base: Path | str | None = None, enabled: bool | None = None) -> CheckpointManager:
    return CheckpointManager(base=base, enabled=enabled)
