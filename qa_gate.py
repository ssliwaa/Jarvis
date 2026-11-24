"""Deterministic zero-RAM frontend & DOM QA gate for `viewer/` changes.

Verifies before any agent patch or team merge is marked healthy:
1. `viewer/index.html` parses cleanly, keeps `capabilities.js` in the final `<script>`
   slot, and pins exact semver + `sha384-...` SRI integrity hashes on remote CDN scripts.
2. Every referenced local CSS/JS asset in `viewer/` exists on disk.
3. Security-sensitive agent surfaces (`agents.js`, `mission.js`) contain zero `.innerHTML` sinks.
4. Every `viewer/*.js` passes `node --check` syntax validation (when Node.js is present).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path


class _ViewerHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts: list[dict] = []
        self.stylesheets: list[str] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = dict(attrs)
        if ad.get("id"):
            self.ids.add(str(ad["id"]))
        if tag == "script" and ad.get("src"):
            self.scripts.append({
                "src": str(ad["src"]),
                "integrity": str(ad.get("integrity") or ""),
                "crossorigin": str(ad.get("crossorigin") or ""),
            })
        elif tag == "link" and ad.get("rel") == "stylesheet" and ad.get("href"):
            self.stylesheets.append(str(ad["href"]))


def _find_node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    hermes_tools = Path.home() / ".hermes" / "tools"
    if hermes_tools.is_dir():
        for cand in sorted(hermes_tools.glob("node-*/bin/node"), reverse=True):
            if cand.is_file() and cand.stat().st_mode & 0o111:
                return str(cand)
    return None


def audit_viewer(project_root: str | Path) -> dict:
    """Run deterministic structural, security, and JS syntax checks on `viewer/`."""
    root = Path(project_root).expanduser().resolve()
    viewer = root / "viewer"
    index_html = viewer / "index.html"
    if not index_html.is_file():
        return {"ok": True, "skipped": True, "issues": [], "checked_js": 0}

    issues: list[str] = []
    html_text = index_html.read_text(encoding="utf-8", errors="replace")
    parser = _ViewerHTMLParser()
    parser.feed(html_text)

    if not parser.scripts:
        issues.append("viewer/index.html: brak tagów <script src=...>")
    else:
        last_src = parser.scripts[-1]["src"]
        if (viewer / "capabilities.js").is_file() and last_src != "capabilities.js":
            issues.append(
                f"viewer/index.html: ostatnim skryptem musi być 'capabilities.js', wykryto {last_src!r}"
            )

    for s in parser.scripts:
        src = s["src"]
        if src.startswith(("http://", "https://")):
            if not re.search(r"@\d+\.\d+\.\d+/", src):
                issues.append(f"Zewnętrzny skrypt bez przypiętej wersji semver: {src}")
            if not re.match(r"^sha384-[A-Za-z0-9+/=]+$", s["integrity"]) or s["crossorigin"] != "anonymous":
                issues.append(f"Zewnętrzny skrypt bez hash SRI sha384 lub crossorigin='anonymous': {src}")
        else:
            clean_rel = src.split("?", 1)[0]
            if not (viewer / clean_rel).is_file():
                issues.append(f"Brak lokalnego pliku skryptu: viewer/{clean_rel}")

    for href in parser.stylesheets:
        if not href.startswith(("http://", "https://")):
            clean_rel = href.split("?", 1)[0]
            if not (viewer / clean_rel).is_file():
                issues.append(f"Brak arkusza stylów: viewer/{clean_rel}")

    for strict_js in ("agents.js", "mission.js"):
        jsp = viewer / strict_js
        if jsp.is_file():
            src_text = jsp.read_text(encoding="utf-8", errors="replace")
            if ".innerHTML" in src_text:
                issues.append(f"viewer/{strict_js}: wykryto niedozwolone użycie '.innerHTML' (ryzyko XSS)")

    node_bin = _find_node()
    checked_js = 0
    if node_bin:
        for js_file in sorted(viewer.glob("*.js")):
            checked_js += 1
            proc = subprocess.run(
                [node_bin, "--check", str(js_file)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if proc.returncode != 0:
                err_line = (proc.stderr or proc.stdout or "syntax error").strip().splitlines()[0]
                issues.append(f"Błąd składni JS w viewer/{js_file.name}: {err_line[:200]}")

    return {
        "ok": len(issues) == 0,
        "skipped": False,
        "checked_js": checked_js,
        "scripts_count": len(parser.scripts),
        "issues": issues,
    }
