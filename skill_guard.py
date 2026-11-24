"""Static safety scan for skill packages.

Adapted from Hermes Agent's ``tools/skills_guard.py`` threat taxonomy (MIT,
Nous Research), trimmed for Jarvis: no install policy or trust tiers, one
deterministic verdict and a bounded findings list. This is an advisory static
scan, not a sandbox: a clean verdict never makes a skill's commands safe.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 60
MAX_FINDINGS = 60
SKIP_DIRS = {".git", ".github", ".hub", ".archive", ".venv", "venv", "node_modules",
             "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
TEXT_SUFFIXES = {".md", ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts",
                 ".json", ".yaml", ".yml", ".toml", ".txt", ".ps1", ".rb", ".go"}

# (regex, pattern id, severity, category, description)
_PATTERNS = [
    # Exfiltration
    (r"curl\s+[^\n]*\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", "env_exfil_curl",
     "high", "exfiltration", "curl interpolates a secret environment variable"),
    (r"wget\s+[^\n]*\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", "env_exfil_wget",
     "high", "exfiltration", "wget interpolates a secret environment variable"),
    (r"(?:fetch|requests\.(?:get|post)|httpx?\.(?:get|post))\s*\([^\n]*(?:KEY|TOKEN|SECRET|PASSWORD)",
     "http_secret", "critical", "exfiltration", "HTTP call interpolates a secret"),
    (r"\bcat\s+(?!>)[^\n]*(?:\.env|credentials|\.netrc|\.pgpass|\.npmrc|\.pypirc)",
     "read_secrets", "critical", "exfiltration", "reads a known credential file"),
    (r"\b(?:\.ssh[/\\]id_(?:rsa|ed25519|ecdsa|dsa)|\.aws[/\\]|\.gnupg[/\\]|\.kube[/\\]|\.docker[/\\]config)",
     "credential_path", "high", "exfiltration", "references a credential store"),
    (r"\bprintenv\b|(?<![A-Za-z0-9_])env\s*\|(?!\|)", "dump_env", "high", "exfiltration",
     "dumps the process environment"),
    (r"^[^#\n]*os\.environ\b(?!\s*\.get\s*\()", "python_environ", "medium", "exfiltration",
     "reads os.environ outside a narrow get()"),
    (r"base64[^\n]*\|\s*(?:sh|bash|zsh|python|perl|ruby|node|eval|source|exec)",
     "encoded_pipe", "critical", "exfiltration", "decodes base64 and pipes it to an interpreter"),
    (r"webhook\.site|requestbin\.com|pipedream\.net|hookbin\.com|pastebin\.com|hastebin\.com",
     "exfil_service", "high", "exfiltration", "references a data-staging service"),
    (r"!\s*\[[^\]]*\]\(https?://[^\)]*\$\{?", "markdown_image_exfil", "high", "exfiltration",
     "markdown image URL interpolates dynamic data"),
    # Prompt injection / concealment
    (r"ignore\s+(?:\w+\s+)*(?:previous|all|above|prior)\s+instructions",
     "ignore_instructions", "critical", "injection", "tells the agent to ignore prior instructions"),
    (r"disregard\s+(?:\w+\s+)*(?:your|all|any)\s+(?:\w+\s+)*(?:instructions|rules|guidelines)",
     "disregard_rules", "critical", "injection", "tells the agent to disregard its rules"),
    (r"system\s+(?:\w+\s+)*prompt\s+(?:\w+\s+)*override", "system_override", "critical",
     "injection", "attempts to override the system prompt"),
    (r"(?:output|reveal|print)\s+(?:\w+\s+)*(?:system|initial)\s+prompt", "prompt_leak", "high",
     "injection", "attempts to extract the system prompt"),
    (r"you\s+are\s+(?:\w+\s+)*now\s+", "role_hijack", "high", "injection",
     "attempts to replace the agent's role"),
    (r"pretend\s+(?:\w+\s+)*(?:you\s+are|to\s+be)\s+", "role_pretend", "high", "injection",
     "asks the agent to assume another identity"),
    (r"do\s+not\s+(?:\w+\s+)*tell\s+(?:\w+\s+)*the\s+user(?!\s+to\s+[\"'])"
     r"(?!.*\b(?:unless|except|until|confirm|verify)\b)", "hide_from_user", "high", "injection",
     "instructs the agent to hide something from the user"),
    (r"<!--[^>]*(?:ignore|forget|disregard|override|system\s+(?:prompt|message)|"
     r"you\s+are\s+now|do\s+not\s+tell)[^>]*-->", "html_comment_injection", "high", "injection",
     "hidden instructions in an HTML comment"),
    (r"display\s*:\s*none", "hidden_content", "medium", "injection",
     "hidden HTML content may carry instructions"),
    # Destructive
    (r"rm\s+-[^\s]*r[^\s]*\s+(?:/|~|\$HOME)(?:\s|$)", "root_rm", "critical",
     "destructive", "recursive delete of / or the home directory"),
    (r"\brmdir\s+[^\n]*(?:\$HOME|~(?:[/\s]|$))", "home_rmdir", "critical", "destructive",
     "removes a home directory path"),
    (r"\bmkfs(?:\.\w+)?\b", "format_filesystem", "critical", "destructive",
     "formats a filesystem"),
    (r"\bdd\s+[^\n]*of=/dev/", "disk_overwrite", "critical", "destructive",
     "writes raw bytes to a block device"),
    (r"chmod\s+(?:-R\s+)?777", "world_writable", "medium", "destructive",
     "sets world-writable permissions"),
    (r"shutil\.rmtree\s*\(\s*[\"']/", "rmtree_root", "high", "destructive",
     "recursively removes an absolute path"),
    (r">\s*/etc/", "system_overwrite", "critical", "destructive",
     "overwrites a system configuration file"),
    # Persistence / privilege
    (r"\bcrontab\b", "cron_persistence", "medium", "persistence", "modifies cron entries"),
    (r"authorized_keys", "ssh_backdoor", "critical", "persistence",
     "modifies SSH authorized keys"),
    (r"/etc/sudoers|visudo", "sudoers", "critical", "persistence",
     "modifies sudo privileges"),
    (r"systemctl\s+(?:enable|start)|/etc/init\.d/", "system_persistence", "medium",
     "persistence", "installs or starts a system service"),
    (r"(?<![\w)\]?])\.(?:bashrc|zshrc|bash_profile|profile|zprofile)\b", "shell_rc",
     "medium", "persistence", "references a shell startup file"),
    # Network / shells
    (r"\b(?:nc|ncat)\s+-[^\s]*[lp]|\bsocat\b[^\n]*\b(?:tcp|udp|exec|system|pty):",
     "reverse_shell", "critical", "network", "opens a listener or reverse shell"),
    (r"/bin/(?:ba|z|k|da)?sh\s+-i\s+[^\n]*>/dev/tcp/", "bash_reverse_shell", "critical",
     "network", "bash reverse shell through /dev/tcp"),
    (r"\b(?:ngrok|localtunnel|serveo|cloudflared)\b", "tunnel", "high", "network",
     "exposes a local service through a tunnel"),
    (r"0\.0\.0\.0:\d+|INADDR_ANY", "bind_all", "high", "network",
     "binds a service to every interface"),
    (r"python[23]?\s+-c\s+[\"']import\s+(?:socket|subprocess)", "python_oneliner",
     "high", "network", "Python one-liner starts a socket or process"),
    (r"\beval\s*\(\s*[\"']", "eval_string", "high", "obfuscation",
     "evaluates a string as code"),
    (r"\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}", "hex_string", "low",
     "obfuscation", "long hex-encoded string may be obfuscated code"),
]
_COMPILED = [(re.compile(pattern, re.I), *rest) for pattern, *rest in _PATTERNS]
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿]")
# API skills commonly pass a key in an Authorization header; that is expected
# configuration, not exfiltration. Strip header arguments before scanning so
# only a secret in the URL/body/query remains suspicious.
_AUTH_HEADER = re.compile(r'''(?i)(?:-H|--header)\s+(?:"[^"]*"|'[^']*'|\S+)''')
_SEVERITY = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass(frozen=True)
class Finding:
    pattern: str
    severity: str
    category: str
    file: str
    line: int
    match: str
    description: str

    def public(self) -> dict:
        return {"pattern": self.pattern, "severity": self.severity,
                "category": self.category, "file": self.file, "line": self.line,
                "match": self.match[:120], "description": self.description}


@dataclass
class Scan:
    verdict: str = "safe"
    findings: list[Finding] = field(default_factory=list)
    files: int = 0

    def public(self) -> dict:
        counts = {level: sum(1 for item in self.findings if item.severity == level)
                  for level in ("critical", "high", "medium", "low")}
        summary = (f"{self.verdict}: {counts['critical']} critical, {counts['high']} high, "
                   f"{counts['medium']} medium finding(s) across {self.files} file(s)")
        return {"verdict": self.verdict, "findings": [item.public() for item in self.findings[:MAX_FINDINGS]],
                "summary": summary, "files": self.files, "counts": counts}


def scan_text(text: str, label: str = "text") -> dict:
    """Scan one text blob (skill body, generated code, prompt)."""
    scan = Scan(files=1)
    for number, line in enumerate(str(text or "").splitlines(), 1):
        scan_line = _AUTH_HEADER.sub(" ", line)
        if _INVISIBLE.search(line):
            scan.findings.append(Finding(
                "invisible_unicode", "high", "injection", label, number,
                _INVISIBLE.sub("", line)[:120], "invisible or bidirectional Unicode"))
        for regex, pattern, severity, category, description in _COMPILED:
            match = regex.search(scan_line)
            if match:
                scan.findings.append(Finding(pattern, severity, category, label, number,
                                             match.group(0).replace("\n", " ")[:120],
                                             description))
    _finish(scan)
    return scan.public()


def _finish(scan: Scan) -> None:
    scan.findings.sort(key=lambda item: (-_SEVERITY.get(item.severity, 0), item.file, item.line))
    levels = {item.severity for item in scan.findings}
    mediums = sum(1 for item in scan.findings if item.severity == "medium")
    if "critical" in levels:
        scan.verdict = "dangerous"
    elif "high" in levels or mediums > 2:
        scan.verdict = "caution"
    else:
        scan.verdict = "safe"


def _files(root: Path):
    if root.is_file():
        return [root]
    found = []
    for path in sorted(root.rglob("*")):
        if len(found) >= MAX_FILES:
            break
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if path.is_file() and path.suffix.casefold() in TEXT_SUFFIXES:
            try:
                if path.stat().st_size <= MAX_FILE_BYTES:
                    found.append(path)
            except OSError:
                continue
    return found


def scan_skill(path) -> dict:
    """Scan a SKILL.md or an entire skill directory; always returns a verdict."""
    root = Path(path)
    if not root.exists():
        return Scan().public() | {"summary": "safe: package not found"}
    files = _files(root)
    scan = Scan(files=len(files))
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        label = file_path.name if file_path.is_file() else str(file_path)
        if root.is_dir():
            try:
                label = file_path.relative_to(root).as_posix()
            except ValueError:
                label = file_path.name
        for number, line in enumerate(text.splitlines(), 1):
            scan_line = _AUTH_HEADER.sub(" ", line)
            if _INVISIBLE.search(line):
                scan.findings.append(Finding(
                    "invisible_unicode", "high", "injection", label, number,
                    _INVISIBLE.sub("", line)[:120], "invisible or bidirectional Unicode"))
            for regex, pattern, severity, category, description in _COMPILED:
                match = regex.search(scan_line)
                if match:
                    scan.findings.append(Finding(
                        pattern, severity, category, label, number,
                        match.group(0).replace("\n", " ")[:120], description))
    _finish(scan)
    result = scan.public()
    if result["verdict"] == "dangerous":
        result["summary"] = "dangerous: critical findings; do not execute this skill without review — " + result["summary"]
    elif result["verdict"] == "caution":
        result["summary"] = "caution: review the findings before following this skill — " + result["summary"]
    return result


def should_block(report: dict) -> bool:
    return str((report or {}).get("verdict") or "") == "dangerous"
