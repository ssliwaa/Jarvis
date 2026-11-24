#!/usr/bin/env python3
"""Run pyflakes over the project and honour per-line `# noqa` probes.

pyflakes has no noqa support of its own, so the availability probes
(`import tkinter  # noqa: F401`) would otherwise make this gate red for a
deliberate pattern.  Any warning on a line carrying `# noqa` is filtered here;
everything else fails the gate.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = ("*.py", "operator_modules/*.py", "features/*.py",
            "tests/*.py", "scripts/*.py")
# Fail closed: a pyflakes run that stalls (hung filesystem, huge tree)
# must turn the gate red, not hang the caller (git_pr_bridge gives the
# lint child 45s; this inner timeout also protects manual invocations).
LINT_TIMEOUT_S = 120.0


def targets() -> list[Path]:
    files: list[Path] = []
    for pattern in PATTERNS:
        for path in sorted(ROOT.glob(pattern)):
            if path.is_file() and path not in files:
                files.append(path)
    return files


def main() -> int:
    files = targets()
    if not files:
        print("lint: no Python files found", file=sys.stderr)
        return 1
    try:
        result = subprocess.run([sys.executable, "-m", "pyflakes", *map(str, files)],
                                 capture_output=True, text=True, cwd=ROOT,
                                 timeout=LINT_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        print(f"lint: pyflakes timed out after {int(LINT_TIMEOUT_S)}s "
              f"over {len(files)} files", file=sys.stderr)
        return 1
    findings: list[str] = []
    for line in (result.stdout + result.stderr).splitlines():
        match = re.match(r"^(.+?):(\d+):(\d+): (.*)$", line)
        if not match:
            findings.append(line)
            continue
        path, lineno, _col, _message = match.groups()
        try:
            source = Path(path).read_text(encoding="utf-8").splitlines()[int(lineno) - 1]
        except (OSError, IndexError):
            source = ""
        if "# noqa" in source:
            continue
        findings.append(line)
    if findings:
        print("\n".join(findings))
        print(f"\nlint: {len(findings)} issue(s)", file=sys.stderr)
        return 1
    print(f"lint: clean ({len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
