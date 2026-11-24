"""Hardened Git Automation Module for Jarvis."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import operator_tools as ops

GIT_TIMEOUT = 15.0
GIT_BINARY = shutil.which("git") or "/usr/bin/git"
BASE_GIT_CMD = [GIT_BINARY, "-c", "core.hooksPath=/dev/null", "--no-pager"]

SAFE_REF_RE = re.compile(r"^[a-zA-Z0-9._/-]{1,120}$")


def _run_git(argv: list[str], cwd: Path, timeout: float = GIT_TIMEOUT) -> tuple[int, str, str]:
    """Execute git with strict argument array, hooks disabled, and no pager."""
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        raise ops.ToolError(f"Git command timed out after {timeout} seconds.")
    except OSError as err:
        raise ops.ToolError(f"Failed to execute git binary: {err}")


def _is_sensitive_git_path(repo_dir: Path, rel_path: str) -> bool:
    """Check if a file in the repository matches sensitive credential patterns."""
    try:
        target = (repo_dir / rel_path).resolve()
    except (ValueError, OSError):
        return True

    if ops.is_sensitive(target):
        return True

    parts = [part.casefold() for part in Path(rel_path).parts]
    sensitive_names = {
        ".env", ".env.local", ".env.production",
        "secrets.json", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
        "credentials.json", "service_account.json", "token.json",
    }
    for part in parts:
        if part in sensitive_names:
            return True
        if part.startswith(".env.") or part.endswith(".pem") or part.endswith(".key"):
            return True
    return False


def git_ops(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute hardened, structured Git operations inside an approved repository."""
    args = arguments if isinstance(arguments, dict) else {}
    action = str(args.get("action") or "status").strip().lower()

    workspace = (context or {}).get("workspace")
    base = Path(workspace) if workspace else ops.HOME

    raw_repo = args.get("repo_path")
    target_repo = str(raw_repo) if raw_repo else str(base)

    try:
        repo_dir = ops.resolve_path(target_repo, base=base, must_exist=True)
    except ops.ToolError as err:
        return {"ok": False, "error": str(err)}

    if ops.is_sensitive(repo_dir):
        return {"ok": False, "error": f"Access to sensitive path {repo_dir.name!r} is refused."}

    if not repo_dir.is_dir():
        return {"ok": False, "error": f"Repository path is not a directory: {repo_dir}"}

    try:
        # Verify repository work tree
        code, out, err = _run_git(list(BASE_GIT_CMD) + ["rev-parse", "--is-inside-work-tree"], cwd=repo_dir, timeout=5.0)
        if code != 0 or out.strip() != "true":
            return {"ok": False, "error": f"Directory {repo_dir} is not a valid git repository."}

        if action == "status":
            code, out, err = _run_git(list(BASE_GIT_CMD) + ["status", "--porcelain=v1", "-b"], cwd=repo_dir)
            if code != 0:
                return {"ok": False, "error": f"git status failed: {err.strip() or out.strip()}"}

            lines = out.splitlines()
            branch = "HEAD"
            staged: list[dict[str, str]] = []
            unstaged: list[dict[str, str]] = []
            untracked: list[str] = []

            for line in lines:
                if line.startswith("## "):
                    branch_part = line[3:].strip()
                    branch = branch_part.split("...")[0].strip()
                    continue
                if len(line) < 4:
                    continue
                x, y = line[0], line[1]
                filepath = line[3:].strip()
                if x == "?" and y == "?":
                    untracked.append(filepath)
                else:
                    if x not in (" ", "?"):
                        staged.append({"path": filepath, "status": x})
                    if y not in (" ", "?"):
                        unstaged.append({"path": filepath, "status": y})

            return {
                "ok": True,
                "result": {
                    "repo_path": str(repo_dir),
                    "branch": branch,
                    "clean": len(staged) == 0 and len(unstaged) == 0 and len(untracked) == 0,
                    "staged": staged,
                    "unstaged": unstaged,
                    "untracked": untracked,
                    "staged_count": len(staged),
                    "unstaged_count": len(unstaged),
                    "untracked_count": len(untracked),
                },
            }

        if action == "diff":
            staged_flag = bool(args.get("staged", False))
            path_filter = args.get("path")
            cmd = list(BASE_GIT_CMD) + ["diff"]
            if staged_flag:
                cmd.append("--cached")

            if path_filter:
                if not isinstance(path_filter, str) or path_filter.startswith("-"):
                    return {"ok": False, "error": "Invalid path parameter for diff."}
                cmd.extend(["--", path_filter])

            code, out, err = _run_git(cmd, cwd=repo_dir)
            if code != 0:
                return {"ok": False, "error": f"git diff failed: {err.strip() or out.strip()}"}

            return {
                "ok": True,
                "result": {
                    "staged": staged_flag,
                    "path": path_filter,
                    "diff": ops.redact(out, limit=12000),
                },
            }

        if action == "log":
            raw_count = args.get("max_count")
            try:
                count = max(1, min(int(raw_count if raw_count is not None else 10), 100))
            except (ValueError, TypeError):
                return {"ok": False, "error": "Parameter 'max_count' must be an integer."}

            revision = args.get("revision")
            cmd = list(BASE_GIT_CMD) + ["log", f"-n{count}", "--pretty=format:%H|%an|%ae|%ad|%s", "--date=iso-strict"]
            if revision:
                if not isinstance(revision, str) or revision.startswith("-") or not SAFE_REF_RE.match(revision):
                    return {"ok": False, "error": f"Invalid revision name: {revision!r}"}
                cmd.append(revision)

            code, out, err = _run_git(cmd, cwd=repo_dir)
            if code != 0:
                return {"ok": False, "error": f"git log failed: {err.strip() or out.strip()}"}

            commits = []
            for line in out.splitlines():
                if not line.strip():
                    continue
                parts = line.split("|", 4)
                if len(parts) == 5:
                    commits.append({
                        "hash": parts[0],
                        "author": parts[1],
                        "email": parts[2],
                        "date": parts[3],
                        "subject": parts[4],
                    })

            return {"ok": True, "result": {"commits": commits, "count": len(commits)}}

        if action == "show":
            revision = str(args.get("revision") or "HEAD").strip()
            if not revision or revision.startswith("-") or not SAFE_REF_RE.match(revision):
                return {"ok": False, "error": f"Invalid revision parameter: {revision!r}"}

            path_filter = args.get("path")
            cmd = list(BASE_GIT_CMD) + ["show", "--stat", revision]
            if path_filter:
                if not isinstance(path_filter, str) or path_filter.startswith("-"):
                    return {"ok": False, "error": "Invalid path parameter for show."}
                cmd.extend(["--", path_filter])

            code, out, err = _run_git(cmd, cwd=repo_dir)
            if code != 0:
                return {"ok": False, "error": f"git show failed: {err.strip() or out.strip()}"}

            return {"ok": True, "result": {"output": ops.redact(out, limit=12000)}}

        if action == "branch":
            branch_action = str(args.get("branch_action") or "list").strip().lower()
            if branch_action == "list":
                code, out, err = _run_git(list(BASE_GIT_CMD) + ["branch", "--list", "-v"], cwd=repo_dir)
                if code != 0:
                    return {"ok": False, "error": f"git branch failed: {err.strip() or out.strip()}"}

                branches = []
                for line in out.splitlines():
                    cleaned = line.strip()
                    if not cleaned:
                        continue
                    current = line.startswith("*")
                    body = cleaned.lstrip("* ")
                    if body.startswith("(HEAD"):
                        # Detached HEAD (and bisect/rebase states) print as
                        # "(HEAD detached at 1a2b3c)" — or localized, e.g.
                        # Polish "(HEAD odłączone na 1a2b3c)" — so match the
                        # marker, not the English phrase: it would otherwise
                        # be reported as a branch literally named "(HEAD".
                        inner_end = body.find(")")
                        inner = body[len("(HEAD"):inner_end] if inner_end > 0 else ""
                        inner_tokens = inner.split() if inner else []
                        sha = inner_tokens[-1] if inner_tokens and len(inner_tokens[-1]) >= 7 else ""
                        branches.append({
                            "name": f"HEAD detached at {sha}" if sha else "HEAD detached",
                            "current": current,
                            "detail": cleaned,
                        })
                        continue
                    bname = body.split()[0] if body.split() else ""
                    if not bname:
                        continue
                    branches.append({"name": bname, "current": current, "detail": cleaned})

                return {"ok": True, "result": {"branches": branches, "count": len(branches)}}

            if branch_action == "create":
                branch_name = str(args.get("branch_name") or "").strip()
                if not branch_name or branch_name.startswith("-") or not SAFE_REF_RE.match(branch_name):
                    return {"ok": False, "error": f"Invalid branch name: {branch_name!r}"}

                code, out, err = _run_git(list(BASE_GIT_CMD) + ["branch", "--", branch_name], cwd=repo_dir)
                if code != 0:
                    return {"ok": False, "error": f"Failed to create branch: {err.strip() or out.strip()}"}

                return {"ok": True, "result": {"created": branch_name}}

            return {"ok": False, "error": f"Unsupported branch action: {branch_action!r}"}

        if action == "commit":
            message = str(args.get("message") or "").strip()
            if not message:
                return {"ok": False, "error": "Parameter 'message' is required for commit action."}

            files = args.get("files")
            if files is not None:
                if not isinstance(files, list):
                    return {"ok": False, "error": "Parameter 'files' must be a list of file paths."}
                for fpath in files:
                    if not isinstance(fpath, str) or not fpath.strip() or fpath.startswith("-"):
                        return {"ok": False, "error": f"Invalid file path in files list: {fpath!r}"}
                    if _is_sensitive_git_path(repo_dir, fpath):
                        return {"ok": False, "error": f"Refusing to stage sensitive credential file: {fpath!r}"}

                add_cmd = list(BASE_GIT_CMD) + ["add", "--"] + [str(f) for f in files]
                code, out, err = _run_git(add_cmd, cwd=repo_dir)
                if code != 0:
                    return {"ok": False, "error": f"git add failed: {err.strip() or out.strip()}"}

            # Inspect all currently staged files
            diff_cmd = list(BASE_GIT_CMD) + ["diff", "--name-only", "--cached"]
            code, out, err = _run_git(diff_cmd, cwd=repo_dir)
            if code != 0:
                return {"ok": False, "error": f"Failed to check staged files: {err.strip() or out.strip()}"}

            staged_files = [line.strip() for line in out.splitlines() if line.strip()]
            if not staged_files:
                return {"ok": False, "error": "No changes staged for commit."}

            for staged_path in staged_files:
                if _is_sensitive_git_path(repo_dir, staged_path):
                    return {
                        "ok": False,
                        "error": f"Refusing to commit: staged file {staged_path!r} matches sensitive credential patterns.",
                    }

            commit_cmd = list(BASE_GIT_CMD) + ["commit", "-m", message]
            code, out, err = _run_git(commit_cmd, cwd=repo_dir)
            if code != 0:
                return {"ok": False, "error": f"git commit failed: {err.strip() or out.strip()}"}

            # Retrieve new commit hash
            _, rev_out, _ = _run_git(list(BASE_GIT_CMD) + ["rev-parse", "HEAD"], cwd=repo_dir)
            commit_hash = rev_out.strip()

            return {
                "ok": True,
                "result": {
                    "committed": True,
                    "commit": commit_hash,
                    "message": message,
                    "staged_files": staged_files,
                },
            }

        return {"ok": False, "error": f"Unsupported action: {action!r}"}

    except ops.ToolError as err:
        return {"ok": False, "error": str(err)}


TOOL = {
    "name": "git_ops",
    "description": (
        "Structured, hardened Git automation for local repositories with hook disabling "
        "and credential protection. Actions: 'status', 'diff', 'log', 'show', 'branch', 'commit'."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["status", "diff", "log", "show", "branch", "commit"],
                "description": "Git operation: 'status', 'diff', 'log', 'show', 'branch', or 'commit'.",
            },
            "repo_path": {
                "type": "string",
                "description": "Path to the local Git repository directory (default: workspace).",
            },
            "staged": {
                "type": "boolean",
                "description": "Compare staged/cached changes (for 'diff').",
            },
            "path": {
                "type": "string",
                "description": "Optional file path filter for 'diff' or 'show'.",
            },
            "max_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "description": "Maximum commits to return for 'log' (default: 10).",
            },
            "revision": {
                "type": "string",
                "description": "Commit SHA, branch, or tag reference for 'log' or 'show'.",
            },
            "branch_action": {
                "type": "string",
                "enum": ["list", "create"],
                "description": "Branch operation ('list' or 'create').",
            },
            "branch_name": {
                "type": "string",
                "description": "Branch name when branch_action='create'.",
            },
            "message": {
                "type": "string",
                "description": "Commit message (required for 'commit').",
            },
            "files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of files to stage before committing (for 'commit').",
            },
        },
        "additionalProperties": False,
    },
    "handler": git_ops,
    "approval": True,
}
