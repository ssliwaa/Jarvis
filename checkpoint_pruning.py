"""Checked history rewrites for the Jarvis checkpoint store.

The checkpoint store is a bare git repository shared by every project.  Its
refs are per-project histories; trimming an old snapshot means rewriting the
ref to a shorter commit chain.  A whole operation — snapshot, restore, prune,
clear — takes one process-wide file lock so a rollback cannot race a snapshot
from another thread or another Jarvis process.

This is a direct adaptation of Hermes Agent's ``checkpoint_pruning.py`` (MIT)
with the Hermes runtime lock replaced by a POSIX ``flock``.
"""
from __future__ import annotations

import contextlib
import fcntl
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


class PruneError(RuntimeError):
    """A checkpoint rewrite or store lock failed."""


GC_PENDING_NAME = ".gc-pending"


def store_lock_path(base: Path) -> Path:
    base = Path(base).resolve()
    return base.with_name(f".{base.name}.lock")


@contextlib.contextmanager
def store_lock(base: Path):
    """Serialize whole checkpoint operations across threads and processes."""
    base = Path(base)
    base.parent.mkdir(parents=True, exist_ok=True)
    # Keep the lock outside the base directory so clear/legacy migration
    # cannot replace the inode another process has locked.
    fd = os.open(store_lock_path(base), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError as error:
            raise PruneError(f"checkpoint store is busy: {base}") from error
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


@dataclass(frozen=True)
class Pruner:
    run_git: Callable
    store: Path
    cwd: str
    timeout: int
    dir_size: Callable[[Path], int]
    refs_prefix: str

    def _git(self, args: list[str], **kwargs) -> str:
        ok, output, error = self.run_git(args, self.store, self.cwd, **kwargs)
        if not ok:
            raise PruneError(f"checkpoint {args[0]} failed: {error}")
        return output

    def reclaim(self) -> None:
        """Expire reflogs and repack; only the periodic prune calls this."""
        self._git(["reflog", "expire", "--expire=now", "--all"])
        self._git(["gc", "--prune=now", "--quiet"], timeout=self.timeout * 3)
        for name in ("refs/heads", "branches"):
            (self.store / name).mkdir(parents=True, exist_ok=True)
        try:
            (self.store / GC_PENDING_NAME).unlink()
        except OSError:
            pass

    def gc_pending(self) -> bool:
        return (self.store / GC_PENDING_NAME).exists()

    def _mark_gc_pending(self) -> None:
        try:
            (self.store / GC_PENDING_NAME).touch()
        except OSError:
            pass

    def _commits(self, ref: str) -> list[str]:
        commits = self._git(["rev-list", "--reverse", ref]).splitlines()
        if not commits:
            raise PruneError(f"checkpoint ref has no readable history: {ref}")
        return commits

    def _rewrite(self, ref: str, original: list[str], keep: list[str], *, gc: bool) -> None:
        parent = None
        for sha in keep:
            metadata = self._git(["log", "-1", "--format=%T%x00%aI%x00%cI%x00%s", sha])
            fields = metadata.split("\x00", 3)
            if len(fields) != 4:
                raise PruneError(f"invalid checkpoint metadata: {sha}")
            tree, author_date, committer_date, message = fields
            args = ["commit-tree", tree, "--no-gpg-sign", "-m", message]
            if parent is not None:
                args += ["-p", parent]
            parent = self._git(
                args,
                extra_env={"GIT_AUTHOR_DATE": author_date, "GIT_COMMITTER_DATE": committer_date},
            )
            if not parent:
                raise PruneError("commit-tree returned no checkpoint identity")
        if parent is None:
            raise PruneError("cannot remove a project's last snapshot")
        # Never overwrite a snapshot published since the history was read.
        self._git(["update-ref", ref, parent, original[-1]])
        if gc:
            self.reclaim()
        else:
            self._mark_gc_pending()

    def trim(self, ref: str, keep_count: int) -> None:
        commits = self._commits(ref)
        keep_count = max(1, keep_count)
        if len(commits) > keep_count:
            self._rewrite(ref, commits, commits[-keep_count:], gc=False)

    def drop_one_round(self, cap_bytes: int) -> bool:
        if cap_bytes <= 0 or self.dir_size(self.store) <= cap_bytes:
            return False
        changed = False
        for ref in self._git(["for-each-ref", "--format=%(refname)", self.refs_prefix]).splitlines():
            commits = self._commits(ref)
            if len(commits) > 1:
                self._rewrite(ref, commits, commits[1:], gc=False)
                changed = True
        return changed

    def enforce_size(self, cap_bytes: int) -> bool:
        if cap_bytes <= 0 or self.dir_size(self.store) <= cap_bytes:
            return True
        self.reclaim()
        if self.dir_size(self.store) <= cap_bytes:
            return True
        refs = self._git(["for-each-ref", "--format=%(refname)", self.refs_prefix]).splitlines()
        for _ in range(20):
            changed = False
            for ref in refs:
                commits = self._commits(ref)
                if len(commits) <= 1:
                    continue
                self._rewrite(ref, commits, commits[1:], gc=True)
                changed = True
                if self.dir_size(self.store) <= cap_bytes:
                    return True
            if not changed:
                break
        return False
