"""Sandboxed Git / GitHub / GitLab PR review & branch bridge for Jarvis.

1. `review_ref_in_sandbox`: checks out any branch, commit, or PR ref (`pull/N/head`)
   into a disposable `git worktree` and runs `scripts/lint.py` / `unittest` inside
   `evolution.sandbox_argv` (`bwrap --unshare-net`), leaving the main checkout untouched.
2. `create_branch_from_outbox`: applies verified agent/team `outbox` changes onto
   a clean Git feature branch (via a temporary worktree) and prepares or opens a PR.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import agent_review
import evolution

BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,80}$")


class GitBridgeError(Exception):
    """Raised when a Git/PR operation fails validation or git execution."""


def _make_worktree_slot(prefix: str) -> tuple[Path, Path]:
    base_dir = "/tmp" if Path("/tmp").is_dir() else None
    holder = Path(tempfile.mkdtemp(prefix=f"jarvis-{prefix}-", dir=base_dir))
    return holder, holder / "wt"


def _git(cwd: Path, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _validate_ref(ref: str) -> str:
    clean = str(ref or "").strip()
    if not clean or clean.startswith("-") or ".." in clean or not BRANCH_RE.match(clean):
        raise GitBridgeError(f"Nieprawidłowa referencja Git: {ref!r}")
    return clean


def review_ref_in_sandbox(repo_dir: str | Path, ref: str,
                          remote: str = "", test_target: str = "") -> dict:
    """Checkout `ref` in an isolated worktree and run lint + tests inside bwrap."""
    if not shutil.which("git"):
        raise GitBridgeError("Brak zainstalowanego narzędzia git.")
    repo = Path(repo_dir).expanduser().resolve()
    if not (repo / ".git").exists():
        raise GitBridgeError(f"Katalog nie jest repozytorium Git: {repo}")

    clean_ref = _validate_ref(ref)
    target_ref = clean_ref
    if remote:
        clean_remote = _validate_ref(remote)
        fetch_ref = f"pull/{clean_ref}/head" if clean_ref.isdigit() else clean_ref
        fetched = _git(repo, ["fetch", "--no-tags", clean_remote, fetch_ref], timeout=45)
        if fetched.returncode != 0:
            raise GitBridgeError(f"git fetch nie powiódł się: {(fetched.stderr or fetched.stdout).strip()[:240]}")
        target_ref = "FETCH_HEAD"

    rev = _git(repo, ["rev-parse", "--verify", target_ref])
    if rev.returncode != 0:
        raise GitBridgeError(f"Nieznana gałąź lub commit: {clean_ref}")
    commit_sha = rev.stdout.strip()

    holder, wt_dir = _make_worktree_slot("pr")
    add_res = _git(repo, ["worktree", "add", "--detach", str(wt_dir), commit_sha])
    if add_res.returncode != 0:
        shutil.rmtree(holder, ignore_errors=True)
        raise GitBridgeError(f"Nie udało się utworzyć worktree: {(add_res.stderr or add_res.stdout).strip()[:240]}")

    try:
        diff_stat = _git(repo, ["diff", "--stat", f"HEAD..{commit_sha}"]).stdout.strip()
        changed_files = [
            ln.strip() for ln in _git(repo, ["diff", "--name-only", f"HEAD..{commit_sha}"]).stdout.splitlines()
            if ln.strip()
        ]

        checks = []
        if (wt_dir / "scripts" / "lint.py").is_file():
            argv = evolution.sandbox_argv([sys.executable, "scripts/lint.py"], readonly=[str(wt_dir)], cwd=wt_dir)
            r_lint = subprocess.run(
                argv, cwd=str(wt_dir), env=evolution._bench_environment(),
                capture_output=True, text=True, timeout=45, check=False,
            )
            checks.append({
                "name": "lint",
                "ok": r_lint.returncode == 0,
                "output": (r_lint.stdout + r_lint.stderr).strip()[-600:],
            })

        if test_target:
            safe_test = _validate_ref(test_target)
            argv = evolution.sandbox_argv(
                [sys.executable, "-m", "unittest", safe_test],
                writable=wt_dir,
                cwd=wt_dir,
            )
            r_ut = subprocess.run(
                argv, cwd=str(wt_dir), env=evolution._bench_environment(),
                capture_output=True, text=True, timeout=90, check=False,
            )
            checks.append({
                "name": "unittest",
                "ok": r_ut.returncode == 0,
                "output": (r_ut.stdout + r_ut.stderr).strip()[-800:],
            })
        else:
            py_files = [wt_dir / f for f in changed_files if f.endswith(".py") and (wt_dir / f).is_file()]
            if py_files:
                ast_cmd = (
                    "import ast, pathlib, sys\n"
                    "for p in sys.argv[1:]:\n"
                    "    ast.parse(pathlib.Path(p).read_text(encoding='utf-8'), filename=p)\n"
                )
                argv = evolution.sandbox_argv(
                    [sys.executable, "-c", ast_cmd, *[str(p) for p in py_files[:30]]],
                    readonly=[str(wt_dir)],
                    cwd=wt_dir,
                )
                r_py = subprocess.run(
                    argv, cwd=str(wt_dir), env=evolution._bench_environment(),
                    capture_output=True, text=True, timeout=30, check=False,
                )
                checks.append({
                    "name": "ast_check",
                    "ok": r_py.returncode == 0,
                    "output": (r_py.stdout + r_py.stderr).strip()[-400:],
                })

        all_ok = all(c["ok"] for c in checks) if checks else True
        return {
            "ok": all_ok,
            "ref": clean_ref,
            "commit": commit_sha,
            "changed_files": changed_files,
            "diff_stat": diff_stat[:1500],
            "checks": checks,
        }
    finally:
        _git(repo, ["worktree", "remove", "--force", str(wt_dir)])
        shutil.rmtree(holder, ignore_errors=True)


def create_branch_from_outbox(repo_dir: str | Path, branch_name: str,
                              outbox_source: str, commit_message: str = "",
                              open_pr: bool = False) -> dict:
    """Apply `outbox_source` onto a new Git branch inside a clean worktree and commit."""
    if not shutil.which("git"):
        raise GitBridgeError("Brak zainstalowanego narzędzia git.")
    repo = Path(repo_dir).expanduser().resolve()
    if not (repo / ".git").exists():
        raise GitBridgeError(f"Katalog nie jest repozytorium Git: {repo}")

    clean_branch = _validate_ref(branch_name)
    holder, wt_dir = _make_worktree_slot("branch")
    add_res = _git(repo, ["worktree", "add", "-b", clean_branch, str(wt_dir), "HEAD"])
    if add_res.returncode != 0:
        shutil.rmtree(holder, ignore_errors=True)
        raise GitBridgeError(f"Nie udało się utworzyć gałęzi {clean_branch}: {(add_res.stderr or add_res.stdout).strip()[:240]}")

    try:
        applied = agent_review.apply_outbox(outbox_source, str(wt_dir))
        if applied.get("applied", 0) == 0:
            raise GitBridgeError(f"Brak zmian w outbox ({outbox_source}) do zapisania na gałęzi.")

        _git(wt_dir, ["add", "-A"])
        msg = str(commit_message or f"jarvis({outbox_source}): apply verified outbox changes").strip()[:240]
        c_res = subprocess.run(
            [
                "git",
                "-c", "user.name=Jarvis Bridge",
                "-c", "user.email=jarvis@local",
                "commit", "-m", msg,
            ],
            cwd=str(wt_dir),
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        )
        if c_res.returncode != 0:
            raise GitBridgeError(f"git commit nie powiódł się: {(c_res.stderr or c_res.stdout).strip()[:240]}")

        commit_sha = _git(wt_dir, ["rev-parse", "HEAD"]).stdout.strip()
        pr_url = ""
        if open_pr and shutil.which("gh"):
            gh_res = subprocess.run(
                ["gh", "pr", "create", "--head", clean_branch, "--title", msg, "--body", f"Automated branch from `{outbox_source}`."],
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if gh_res.returncode == 0:
                pr_url = gh_res.stdout.strip()

        return {
            "ok": True,
            "branch": clean_branch,
            "commit": commit_sha,
            "files": applied.get("files", []),
            "pr_url": pr_url,
            "push_hint": f"git push -u origin {clean_branch}",
        }
    finally:
        _git(repo, ["worktree", "remove", "--force", str(wt_dir)])
        shutil.rmtree(holder, ignore_errors=True)
