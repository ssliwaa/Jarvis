"""Deterministic zero-RAM secret-leak & dangerous-AST security scanner for Jarvis.

Blocks autonomous agent patches or PR branches before merge when they introduce:
  1. Hardcoded cloud/API secrets (`sk-ant-...`, `sk-proj-...`, `AIzaSy...`, `ghp_...`,
     `github_pat_...`, `gsk_...`, Telegram bot tokens, PEM private keys).
  2. High-risk Python AST sinks (`subprocess.*(..., shell=True)`, `os.system(...)`,
     `pickle.loads(...)`, `marshal.loads(...)`, unsafe `yaml.load(...)`).
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path

SCAN_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".toml", ".yaml", ".yml", ".sh", ".env", ".md",
}
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "artifacts", ".orbit-backup",
    ".jarvis-mcp-backups", ".hermes", ".jarvis-tools",
}
MAX_SCAN_BYTES = 350_000
MAX_SCAN_FILES = 1500

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic_key", re.compile(r"\bsk-ant-api\d{2}-[A-Za-z0-9_\-]{20,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj|live)-[A-Za-z0-9_\-]{20,}")),
    ("google_api_key", re.compile(r"\bAIzaSy[A-Za-z0-9_\-]{33}\b")),
    ("github_pat", re.compile(r"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("groq_key", re.compile(r"\bgsk_[A-Za-z0-9]{28,}\b")),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{31,35}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
)

SUBPROCESS_CALLS = {"run", "Popen", "call", "check_call", "check_output"}


def _mask_match(raw: str) -> str:
    if len(raw) <= 10:
        return "***"
    return f"{raw[:6]}…{raw[-3:]}"


def _call_qualname(node: ast.Call) -> tuple[str, str]:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id, func.attr
    if isinstance(func, ast.Name):
        return "", func.id
    return "", ""


def scan_python_ast(rel_path: str, source: str) -> list[dict]:
    """Inspect Python AST for `shell=True`, `os.system`, `pickle.loads`, and unsafe `yaml.load`."""
    findings: list[dict] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        mod_name, fn_name = _call_qualname(node)
        lineno = int(getattr(node, "lineno", 0) or 0)

        if mod_name == "subprocess" and fn_name in SUBPROCESS_CALLS:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    findings.append({
                        "severity": "high",
                        "kind": "ast_shell_true",
                        "path": rel_path,
                        "line": lineno,
                        "detail": f"Wywołanie subprocess.{fn_name}(..., shell=True) grozi wstrzyknięciem powłoki.",
                    })
        elif mod_name == "os" and fn_name == "system":
            findings.append({
                "severity": "high",
                "kind": "ast_os_system",
                "path": rel_path,
                "line": lineno,
                "detail": "Wywołanie os.system(...) uruchamia powłokę; użyj subprocess.run([...], shell=False).",
            })
        elif mod_name in ("pickle", "marshal") and fn_name in ("load", "loads"):
            findings.append({
                "severity": "high",
                "kind": f"ast_{mod_name}_loads",
                "path": rel_path,
                "line": lineno,
                "detail": f"Niezaufana deserializacja {mod_name}.{fn_name}(...) pozwala na wykonanie kodu.",
            })
        elif mod_name == "yaml" and fn_name == "load":
            has_loader = any(kw.arg == "Loader" for kw in node.keywords)
            if not has_loader:
                findings.append({
                    "severity": "high",
                    "kind": "ast_yaml_unsafe_load",
                    "path": rel_path,
                    "line": lineno,
                    "detail": "yaml.load(...) bez SafeLoader; użyj yaml.safe_load(...).",
                })
    return findings


def scan_text_secrets(rel_path: str, text: str) -> list[dict]:
    """Scan file lines for hardcoded API keys, tokens, and PEM private keys."""
    findings: list[dict] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if "jarvis-sec:ignore" in line:
            continue
        for rule_name, pattern in SECRET_PATTERNS:
            m = pattern.search(line)
            if m:
                findings.append({
                    "severity": "critical",
                    "kind": f"secret_{rule_name}",
                    "path": rel_path,
                    "line": idx,
                    "detail": f"Wykryto potencjalny sekret ({rule_name}: {_mask_match(m.group(0))}).",
                })
    return findings


def scan_directory(root_dir: str | Path, *, include_tests: bool = False) -> dict:
    """Scan a repository/worktree for hardcoded secrets and high-risk Python AST sinks."""
    root = Path(root_dir).expanduser().resolve()
    if not root.is_dir():
        return {"ok": False, "scanned_files": 0, "findings": [], "error": f"Brak katalogu: {root}"}

    findings: list[dict] = []
    scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in sorted(dirnames)
            if d not in SKIP_DIRS
            and not d.startswith(".jarvis-")
            and (include_tests or d != "tests")
        ]
        for fname in sorted(filenames):
            if scanned >= MAX_SCAN_FILES:
                break
            if not include_tests and (fname.startswith("test_") or fname.endswith("_test.py")):
                continue
            fpath = Path(dirpath) / fname
            if fpath.is_symlink() or fpath.suffix.lower() not in SCAN_SUFFIXES:
                continue
            try:
                st = fpath.stat()
            except OSError:
                continue
            if st.st_size > MAX_SCAN_BYTES:
                continue
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = str(fpath.relative_to(root)).replace("\\", "/")
            scanned += 1
            findings.extend(scan_text_secrets(rel, text))
            if fpath.suffix.lower() == ".py":
                findings.extend(scan_python_ast(rel, text))

    critical_or_high = [f for f in findings if f["severity"] in ("critical", "high")]
    return {
        "ok": len(critical_or_high) == 0,
        "scanned_files": scanned,
        "findings_count": len(findings),
        "findings": findings[:50],
    }
