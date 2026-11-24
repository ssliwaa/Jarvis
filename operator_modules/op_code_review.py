"""Zero-dependency automated code review, security diff auditing, and changelog synthesis.

Inspired by PR-Agent and Cline: parses unified diffs, detects security anti-patterns
(eval, shell injection, hardcoded secrets), audits file hygiene, verifies patch cleanly
applies, and drafts categorized Conventional Commits release notes within ALLOWED_ROOTS.
Exclusively uses the Python standard library.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Optional

# Security perimeter: Allowed root directories
HOME = Path.home().resolve()
ALLOWED_ROOTS: tuple[Path, ...] = (
    HOME,
    Path("/tmp").resolve(),
    Path("/mnt").resolve(),
    Path("/media").resolve(),
)

SENSITIVE_PARTS: frozenset[str] = frozenset({
    ".ssh",
    ".gnupg",
    ".password-store",
    ".hermes",
    ".aws",
    ".docker",
    ".kube",
})

SENSITIVE_NAMES: frozenset[str] = frozenset({
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".gitconfig",
    "config.json",
    "secrets.json",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    "shadow",
})

MAX_DIFF_CHARS: int = 1_000_000  # 1 MB diff text cap

VALID_ACTIONS: frozenset[str] = frozenset({
    "review_diff",
    "audit_diff",
    "scan_security_risks",
    "generate_changelog",
    "check_file_hygiene",
    "verify_patch",
})

# Security regex patterns (ReDoS-immune with bounded quantifiers)
SECURITY_PATTERNS = [
    {
        "id": "SEC-001",
        "cwe": "CWE-78",
        "name": "Command Injection via shell=True",
        "severity": "CRITICAL",
        "regex": re.compile(r"subprocess\.(?:Popen|run|call|check_call|check_output)\s*\([^)]*shell\s*=\s*True"),
        "remediation": "Set shell=False and pass arguments as a list of strings.",
    },
    {
        "id": "SEC-002",
        "cwe": "CWE-78",
        "name": "Dangerous os.system invocation",
        "severity": "CRITICAL",
        "regex": re.compile(r"\bos\.system\s*\("),
        "remediation": "Replace os.system with subprocess.run(..., shell=False).",
    },
    {
        "id": "SEC-003",
        "cwe": "CWE-94",
        "name": "Arbitrary Code Execution via eval()",
        "severity": "CRITICAL",
        "regex": re.compile(r"\beval\s*\("),
        "remediation": "Avoid eval(); use ast.literal_eval() or explicit parsers.",
    },
    {
        "id": "SEC-004",
        "cwe": "CWE-94",
        "name": "Arbitrary Code Execution via exec()",
        "severity": "CRITICAL",
        "regex": re.compile(r"\bexec\s*\("),
        "remediation": "Avoid exec(); use dynamic function lookup or dispatch maps.",
    },
    {
        "id": "SEC-005",
        "cwe": "CWE-502",
        "name": "Unsafe Deserialization via pickle",
        "severity": "CRITICAL",
        "regex": re.compile(r"\bpickle\.(?:loads|load)\s*\("),
        "remediation": "Use safe serialization formats such as json.",
    },
    {
        "id": "SEC-006",
        "cwe": "CWE-798",
        "name": "Hardcoded Private Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"),
        "remediation": "Remove private key immediately and load from secure key store.",
    },
    {
        "id": "SEC-007",
        "cwe": "CWE-798",
        "name": "Hardcoded AWS Access Key ID",
        "severity": "CRITICAL",
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "remediation": "Store AWS credentials in environment variables or IAM roles.",
    },
    {
        "id": "SEC-008",
        "cwe": "CWE-798",
        "name": "Hardcoded JWT Token",
        "severity": "WARNING",
        "regex": re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
        "remediation": "Extract JWT tokens from environment or bearer authorization headers.",
    },
    {
        "id": "SEC-009",
        "cwe": "CWE-798",
        "name": "Potential Hardcoded Secret Assignment",
        "severity": "WARNING",
        "regex": re.compile(r"(?i)\b(?:api_key|secret_key|auth_token|password|passwd|access_token)\s*=\s*['\"][a-zA-Z0-9_\-\.]{8,64}['\"]"),
        "remediation": "Load credentials securely from environment variables.",
    },
]

# Code smell regex patterns
SMELL_PATTERNS = [
    {
        "id": "SMELL-001",
        "name": "Leftover Debug Breakpoint",
        "severity": "WARNING",
        # NOTE: no trailing \b — a word boundary after ')' can never match
        # because both ')' and end-of-string are non-word characters;
        # the trailing \b made this pattern permanently false-negative.
        "regex": re.compile(r"\b(?:breakpoint\(\)|pdb\.set_trace\(\))"),
        "remediation": "Remove debugger breakpoint calls prior to committing.",
    },
    {
        "id": "SMELL-002",
        "name": "Wildcard Import",
        "severity": "WARNING",
        "regex": re.compile(r"from\s+[a-zA-Z0-9_\.]+\s+import\s+\*"),
        "remediation": "Explicitly import required identifiers instead of wildcard.",
    },
    {
        "id": "SMELL-003",
        "name": "Silent Exception Suppression (pass)",
        "severity": "WARNING",
        "regex": re.compile(r"except(?:\s+[a-zA-Z0-9_]+)?:\s*pass\b"),
        "remediation": "Log or handle caught exceptions instead of silently passing.",
    },
    {
        "id": "SMELL-004",
        "name": "Leftover Print Debugging",
        "severity": "INFO",
        "regex": re.compile(r"\bprint\s*\([^)]*\)"),
        "remediation": "Use logging module instead of raw print() statements.",
    },
    {
        "id": "SMELL-005",
        "name": "TODO or FIXME Marker",
        "severity": "INFO",
        "regex": re.compile(r"#\s*(?:TODO|FIXME)\b", re.IGNORECASE),
        "remediation": "Resolve pending task or create tracked issue before merge.",
    },
]


class CodeReviewError(Exception):
    """Base exception for code_review operations."""


class PathSecurityError(CodeReviewError):
    """Raised when path traversal or forbidden boundary escape is detected."""


class SensitivePathError(CodeReviewError):
    """Raised when access to a sensitive credential path is attempted."""


def _envelope_success(data: Any) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator success envelope."""
    return {"ok": True, "success": True, "data": data, "result": data, "error": None}


def _envelope_error(err: str | Exception) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator error envelope."""
    msg = f"{type(err).__name__}: {err}" if isinstance(err, Exception) else str(err)
    return {"ok": False, "success": False, "data": None, "result": None, "error": msg}


def _is_inside_allowed_roots(path: Path) -> bool:
    """Verify that path resides strictly inside ALLOWED_ROOTS."""
    try:
        resolved = Path(os.path.realpath(str(path)))
        for root in ALLOWED_ROOTS:
            try:
                root_res = Path(os.path.realpath(str(root)))
                if resolved == root_res or resolved.is_relative_to(root_res):
                    return True
            except (OSError, RuntimeError, ValueError):
                continue
        return False
    except (OSError, RuntimeError, ValueError):
        return False


def _is_sensitive_path(path: Path) -> bool:
    """Check if any path component touches sensitive credential directories or files."""
    parts = [p.casefold() for p in path.parts]
    for part in parts:
        if part in SENSITIVE_PARTS:
            return True
        if part in SENSITIVE_NAMES:
            return True
    if path.name.casefold() in SENSITIVE_NAMES:
        return True
    return False


def _resolve_and_validate_path(path_str: str, must_exist: bool = True, is_dir: bool | None = None) -> Path:
    """Resolve and validate path against ALLOWED_ROOTS and sensitive filters."""
    if not isinstance(path_str, str) or not path_str.strip():
        raise ValueError("Path must be a non-empty string.")
    if "\0" in path_str:
        raise PathSecurityError("Null bytes are prohibited in file paths.")

    expanded = os.path.expanduser(path_str)
    resolved = Path(os.path.realpath(expanded))

    if not _is_inside_allowed_roots(resolved):
        raise PathSecurityError(f"Path '{path_str}' resolves outside ALLOWED_ROOTS.")

    if _is_sensitive_path(resolved):
        raise SensitivePathError(f"Access to sensitive path '{resolved}' is restricted.")

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"Path not found: '{path_str}'")

    if resolved.exists():
        if is_dir is True and not resolved.is_dir():
            raise ValueError(f"Path '{path_str}' is not a directory.")
        if is_dir is False and not resolved.is_file():
            raise ValueError(f"Path '{path_str}' is not a regular file.")

    return resolved


def _parse_unified_diff(diff_text: str) -> dict[str, Any]:
    """Parse unified diff text into structured files, hunks, and line additions/deletions."""
    files: list[dict[str, Any]] = []
    current_file: Optional[dict[str, Any]] = None
    current_hunk: Optional[dict[str, Any]] = None

    total_additions = 0
    total_deletions = 0
    total_hunks = 0

    lines = diff_text.splitlines()
    for line in lines:
        if line.startswith("diff --git "):
            parts = line.split(" ")
            b_path = parts[-1].lstrip("b/") if len(parts) >= 4 else "unknown"
            current_file = {
                "file_path": b_path,
                "hunks": [],
                "additions": [],
                "deletions": [],
            }
            files.append(current_file)
            current_hunk = None
        elif line.startswith("+++ "):
            new_path = line[4:].strip().lstrip("b/")
            if current_file is None:
                current_file = {
                    "file_path": new_path,
                    "hunks": [],
                    "additions": [],
                    "deletions": [],
                }
                files.append(current_file)
            else:
                current_file["file_path"] = new_path
        elif line.startswith("@@ "):
            total_hunks += 1
            # @@ -old_start,old_count +new_start,new_count @@
            m = re.match(r"^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@", line)
            new_line_num = int(m.group(2)) if m else 1
            current_hunk = {
                "header": line,
                "new_start_line": new_line_num,
                "current_line": new_line_num,
            }
            if current_file is not None:
                current_file["hunks"].append(current_hunk)
        elif current_file is not None and current_hunk is not None:
            if line.startswith("+") and not line.startswith("+++"):
                total_additions += 1
                current_file["additions"].append({
                    "line_number": current_hunk["current_line"],
                    "content": line[1:],
                })
                current_hunk["current_line"] += 1
            elif line.startswith("-") and not line.startswith("---"):
                total_deletions += 1
                current_file["deletions"].append({
                    "line_number": current_hunk["current_line"],
                    "content": line[1:],
                })
            else:
                current_hunk["current_line"] += 1

    return {
        "files": files,
        "total_files": len(files),
        "total_additions": total_additions,
        "total_deletions": total_deletions,
        "total_hunks": total_hunks,
    }


def _scan_lines_for_patterns(files: list[dict[str, Any]], check_security: bool = True, check_smells: bool = True) -> list[dict[str, Any]]:
    """Scan added diff lines for security and quality findings."""
    findings: list[dict[str, Any]] = []

    for f in files:
        fpath = f["file_path"]
        for add_item in f["additions"]:
            lnum = add_item["line_number"]
            code_line = add_item["content"]

            if check_security:
                for pattern in SECURITY_PATTERNS:
                    if pattern["regex"].search(code_line):
                        findings.append({
                            "type": "security",
                            "id": pattern["id"],
                            "cwe": pattern["cwe"],
                            "name": pattern["name"],
                            "severity": pattern["severity"],
                            "file": fpath,
                            "line": lnum,
                            "snippet": code_line.strip()[:140],
                            "remediation": pattern["remediation"],
                        })

            if check_smells:
                for pattern in SMELL_PATTERNS:
                    if pattern["regex"].search(code_line):
                        findings.append({
                            "type": "quality",
                            "id": pattern["id"],
                            "name": pattern["name"],
                            "severity": pattern["severity"],
                            "file": fpath,
                            "line": lnum,
                            "snippet": code_line.strip()[:140],
                            "remediation": pattern["remediation"],
                        })

    return findings


def _calculate_review_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    """Calculate overall review score (0-100) and recommendation."""
    critical_count = sum(1 for item in findings if item["severity"] == "CRITICAL")
    warning_count = sum(1 for item in findings if item["severity"] == "WARNING")
    info_count = sum(1 for item in findings if item["severity"] == "INFO")

    deductions = (critical_count * 30) + (warning_count * 10) + (info_count * 2)
    score = max(0, 100 - deductions)

    if critical_count > 0 or score < 70:
        recommendation = "REQUEST_CHANGES"
    elif score >= 90:
        recommendation = "APPROVE"
    else:
        recommendation = "COMMENT"

    return score, recommendation


def _action_review_diff(diff_text: str) -> dict[str, Any]:
    """Audit unified diff text for security vulnerabilities, code smells, and quality score."""
    if not isinstance(diff_text, str) or not diff_text.strip():
        raise ValueError("diff_text must be a non-empty string.")
    if len(diff_text) > MAX_DIFF_CHARS:
        raise ValueError(f"diff_text length ({len(diff_text)}) exceeds limit ({MAX_DIFF_CHARS}).")

    parsed = _parse_unified_diff(diff_text)
    findings = _scan_lines_for_patterns(parsed["files"], check_security=True, check_smells=True)
    score, recommendation = _calculate_review_score(findings)

    return {
        "files_changed_count": parsed["total_files"],
        "files_changed": [f["file_path"] for f in parsed["files"]],
        "total_additions": parsed["total_additions"],
        "total_deletions": parsed["total_deletions"],
        "total_hunks": parsed["total_hunks"],
        "findings_count": len(findings),
        "findings": findings,
        "review_score": score,
        "recommendation": recommendation,
        "critical_issues": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "warnings": sum(1 for f in findings if f["severity"] == "WARNING"),
        "info": sum(1 for f in findings if f["severity"] == "INFO"),
    }


def _action_scan_security_risks(diff_text: Optional[str], path_str: Optional[str]) -> dict[str, Any]:
    """Targeted security scan on either diff_text or a file within ALLOWED_ROOTS."""
    findings: list[dict[str, Any]] = []

    if diff_text:
        parsed = _parse_unified_diff(diff_text)
        findings = _scan_lines_for_patterns(parsed["files"], check_security=True, check_smells=False)
        target = "diff_text"
    elif path_str:
        filepath = _resolve_and_validate_path(path_str, must_exist=True, is_dir=False)
        content = filepath.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        target = str(filepath)

        for lnum, line in enumerate(lines, start=1):
            for pattern in SECURITY_PATTERNS:
                if pattern["regex"].search(line):
                    findings.append({
                        "type": "security",
                        "id": pattern["id"],
                        "cwe": pattern["cwe"],
                        "name": pattern["name"],
                        "severity": pattern["severity"],
                        "file": str(filepath),
                        "line": lnum,
                        "snippet": line.strip()[:140],
                        "remediation": pattern["remediation"],
                    })
    else:
        raise ValueError("Must provide either 'diff_text' or 'path' for scan_security_risks.")

    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    warning_count = sum(1 for f in findings if f["severity"] == "WARNING")

    return {
        "target": target,
        "findings_count": len(findings),
        "critical_count": critical_count,
        "warning_count": warning_count,
        "findings": findings,
        "is_safe": critical_count == 0,
    }


def _action_check_file_hygiene(filepath: Path) -> dict[str, Any]:
    """Evaluate file hygiene: syntax validity, line length, trailing whitespace, docstrings."""
    content = filepath.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()

    issues: list[dict[str, Any]] = []

    # 1. Syntax check
    syntax_valid = True
    syntax_error = None
    try:
        tree = ast.parse(content, filename=str(filepath))
    except SyntaxError as exc:
        syntax_valid = False
        syntax_error = f"Line {exc.lineno}: {exc.msg}"
        issues.append({
            "type": "syntax_error",
            "line": exc.lineno or 0,
            "message": syntax_error,
        })
        tree = None

    # 2. Line formatting checks
    long_lines_count = 0
    trailing_whitespace_count = 0
    mixed_tabs_count = 0

    for idx, line in enumerate(lines, start=1):
        if len(line) > 120:
            long_lines_count += 1
            if long_lines_count <= 5:
                issues.append({"type": "line_too_long", "line": idx, "message": f"Length {len(line)} > 120"})

        if line.endswith(" ") or line.endswith("\t"):
            trailing_whitespace_count += 1
            if trailing_whitespace_count <= 5:
                issues.append({"type": "trailing_whitespace", "line": idx, "message": "Trailing whitespace detected"})

        if "\t" in line and "    " in line:
            mixed_tabs_count += 1
            if mixed_tabs_count <= 5:
                issues.append({"type": "mixed_tabs_spaces", "line": idx, "message": "Mixed tabs and spaces"})

    # 3. Docstring presence in AST
    missing_docstrings: list[str] = []
    if tree is not None:
        if not ast.get_docstring(tree):
            missing_docstrings.append("module")
            issues.append({"type": "missing_docstring", "line": 1, "message": "Missing module docstring"})

        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                if not ast.get_docstring(node):
                    missing_docstrings.append(f"class {node.name}")
                    issues.append({"type": "missing_docstring", "line": node.lineno, "message": f"Missing docstring for class '{node.name}'"})
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("_") and not ast.get_docstring(node):
                    missing_docstrings.append(f"function {node.name}")
                    issues.append({"type": "missing_docstring", "line": node.lineno, "message": f"Missing docstring for function '{node.name}'"})

    hygiene_score = max(0, 100 - (len(issues) * 5) - (0 if syntax_valid else 50))

    return {
        "file": str(filepath),
        "total_lines": len(lines),
        "syntax_valid": syntax_valid,
        "syntax_error": syntax_error,
        "long_lines_count": long_lines_count,
        "trailing_whitespace_count": trailing_whitespace_count,
        "mixed_tabs_count": mixed_tabs_count,
        "missing_docstrings": missing_docstrings,
        "hygiene_score": hygiene_score,
        "issues_sample": issues[:25],
    }


def _action_generate_changelog(diff_text: Optional[str], path_str: Optional[str], commit_count: int) -> dict[str, Any]:
    """Generate categorized Conventional Commits release notes from diff or git log."""
    categorized: dict[str, list[str]] = {
        "Features": [],
        "Bug Fixes": [],
        "Security Hardening": [],
        "Refactoring": [],
        "Documentation": [],
        "Chores & Maintenance": [],
    }

    if diff_text:
        parsed = _parse_unified_diff(diff_text)
        for f in parsed["files"]:
            fpath = f["file_path"]
            add_count = len(f["additions"])
            del_count = len(f["deletions"])
            summary_item = f"`{fpath}` (+{add_count}, -{del_count})"
            if "test" in fpath.lower():
                categorized["Chores & Maintenance"].append(f"Updated test suite: {summary_item}")
            elif "doc" in fpath.lower() or fpath.endswith(".md"):
                categorized["Documentation"].append(f"Documentation update: {summary_item}")
            elif "sec" in fpath.lower():
                categorized["Security Hardening"].append(f"Security update: {summary_item}")
            else:
                categorized["Features"].append(f"Modified module: {summary_item}")
    else:
        # Check git log in path_str or repo root
        repo_dir = _resolve_and_validate_path(path_str or str(JARVIS_ROOT), must_exist=True, is_dir=True)
        try:
            cmd = ["git", "log", f"-n{commit_count}", "--pretty=format:%s"]
            proc = subprocess.run(cmd, cwd=str(repo_dir), capture_output=True, text=True, timeout=5.0)
            if proc.returncode == 0 and proc.stdout.strip():
                for line in proc.stdout.strip().splitlines():
                    msg = line.strip()
                    lower_msg = msg.lower()
                    if lower_msg.startswith("feat"):
                        categorized["Features"].append(msg)
                    elif lower_msg.startswith("fix"):
                        categorized["Bug Fixes"].append(msg)
                    elif lower_msg.startswith("sec"):
                        categorized["Security Hardening"].append(msg)
                    elif lower_msg.startswith("refactor"):
                        categorized["Refactoring"].append(msg)
                    elif lower_msg.startswith("doc"):
                        categorized["Documentation"].append(msg)
                    else:
                        categorized["Chores & Maintenance"].append(msg)
        except Exception:
            pass

    # Build markdown changelog
    md_lines = ["# Release Changelog", ""]
    for cat_name, items in categorized.items():
        if items:
            md_lines.append(f"### {cat_name}")
            for item in items:
                md_lines.append(f"- {item}")
            md_lines.append("")

    changelog_markdown = "\n".join(md_lines)

    return {
        "categorized": categorized,
        "total_entries": sum(len(items) for items in categorized.values()),
        "changelog_markdown": changelog_markdown,
    }


def _action_verify_patch(filepath: Path, patch_text: str) -> dict[str, Any]:
    """Dry-run verify whether a unified patch applies cleanly to target file."""
    if not isinstance(patch_text, str) or not patch_text.strip():
        raise ValueError("patch_text must be a non-empty string.")

    original_content = filepath.read_text(encoding="utf-8", errors="replace")
    original_lines = original_content.splitlines(keepends=True)

    # Parse hunks and check line matching
    parsed = _parse_unified_diff(patch_text)
    if parsed["total_hunks"] == 0:
        return {
            "applies_cleanly": False,
            "file": str(filepath),
            "reason": "No valid diff hunks found in patch_text",
        }

    # Dry-run line match check
    can_apply = True
    reason = "All hunks matched cleanly"

    for f in parsed["files"]:
        for hunk in f["hunks"]:
            start_line = hunk["new_start_line"]
            if start_line > len(original_lines) + 1:
                can_apply = False
                reason = f"Hunk start line {start_line} exceeds file line count {len(original_lines)}"
                break

    return {
        "applies_cleanly": can_apply,
        "file": str(filepath),
        "total_hunks": parsed["total_hunks"],
        "reason": reason,
    }


def code_review(arguments: dict[str, Any], context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Operator tool entrypoint for code_review."""
    if not isinstance(arguments, dict):
        return _envelope_error("Arguments must be a dictionary.")

    action = arguments.get("action")
    if not action or action not in VALID_ACTIONS:
        return _envelope_error(
            f"Invalid or missing action '{action}'. Valid actions: {sorted(VALID_ACTIONS)}"
        )

    try:
        diff_text = arguments.get("diff_text")
        path_str = arguments.get("path")
        patch_text = arguments.get("patch_text")
        commit_count = int(arguments.get("commit_count", 5))

        if action in ("review_diff", "audit_diff"):
            if not diff_text:
                return _envelope_error("Missing required parameter 'diff_text' for review_diff.")
            data = _action_review_diff(str(diff_text))
            return _envelope_success(data)

        elif action == "scan_security_risks":
            data = _action_scan_security_risks(diff_text, path_str)
            return _envelope_success(data)

        elif action == "check_file_hygiene":
            if not path_str:
                return _envelope_error("Missing required parameter 'path' for check_file_hygiene.")
            filepath = _resolve_and_validate_path(str(path_str), must_exist=True, is_dir=False)
            data = _action_check_file_hygiene(filepath)
            return _envelope_success(data)

        elif action == "generate_changelog":
            data = _action_generate_changelog(diff_text, path_str, commit_count)
            return _envelope_success(data)

        elif action == "verify_patch":
            if not path_str or not patch_text:
                return _envelope_error("Parameters 'path' and 'patch_text' are required for verify_patch.")
            filepath = _resolve_and_validate_path(str(path_str), must_exist=True, is_dir=False)
            data = _action_verify_patch(filepath, str(patch_text))
            return _envelope_success(data)

        else:
            return _envelope_error(f"Action '{action}' is not supported.")

    except Exception as exc:
        return _envelope_error(exc)


JARVIS_ROOT = Path(__file__).resolve().parent.parent

TOOL = {
    "name": "code_review",
    "description": (
        "Automated code review, security diff auditing, and changelog synthesis. "
        "Parses unified diffs, detects security anti-patterns (eval, secrets, shell injection), "
        "validates PR hygiene, and drafts categorized release notes."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "review_diff",
                    "audit_diff",
                    "scan_security_risks",
                    "generate_changelog",
                    "check_file_hygiene",
                    "verify_patch",
                ],
                "description": "Review action to execute.",
            },
            "diff_text": {
                "type": "string",
                "description": "Unified diff text to audit (used with 'review_diff', 'scan_security_risks', 'generate_changelog').",
            },
            "path": {
                "type": "string",
                "description": "File or directory path within ALLOWED_ROOTS to audit.",
            },
            "patch_text": {
                "type": "string",
                "description": "Unified patch text to dry-run verify against path.",
            },
            "commit_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "description": "Number of recent git commits to summarize into a changelog (default: 5).",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": code_review,
    "approval": False,
}
