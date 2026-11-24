"""Read-only skill/procedure library for Jarvis.

A skill is a directory containing ``SKILL.md`` with a small YAML frontmatter.
Jarvis can inspect and follow a skill; it cannot execute arbitrary code from it.

Roots, in priority order: bundled ``skills/`` next to this file, user skills in
``~/.jarvis-tools/skills``, then the Hermes library in ``~/.hermes/skills`` and
``~/.hermes/plugins/*/skills``. Hermes skills are nested one or two levels deep,
so discovery walks each root instead of assuming ``<root>/<name>/SKILL.md``.
"""
from __future__ import annotations

import re
import time
from pathlib import Path

import skill_guard

ROOT = Path(__file__).resolve().parent / "skills"
USER = Path.home() / ".jarvis-tools" / "skills"
HERMES = Path.home() / ".hermes" / "skills"
HERMES_PLUGINS = Path.home() / ".hermes" / "plugins"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv"}
MAX_DEPTH = 4
CACHE_TTL = 30.0


def _frontmatter(text: str) -> tuple[dict, str]:
    if not text.startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text
    meta = {}
    for line in parts[1].splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            meta[key.strip().lower()] = value.strip().strip('"').strip("'")
    return meta, parts[2].lstrip("\n")


class SkillStore:
    def __init__(self, *roots: Path):
        self.roots = tuple(Path(root) for root in (roots or (ROOT, USER, HERMES, HERMES_PLUGINS)))
        self._cache_at = 0.0
        self._cache_rows: list[dict] | None = None
        self._cache_paths: dict[str, Path] = {}
        self._cache_sig = None

    def _roots_mtime(self) -> tuple:
        out = []
        for root in self.roots:
            try:
                st = root.stat()
                out.append((str(root), st.st_mtime_ns))
            except OSError:
                out.append((str(root), 0))
        return tuple(out)

    def _paths(self):
        for root in self.roots:
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("SKILL.md")):
                if path.is_symlink():
                    continue
                try:
                    relative = path.relative_to(root)
                except ValueError:
                    continue
                if len(relative.parts) - 1 > MAX_DEPTH:
                    continue
                if any(part in SKIP_DIRS for part in relative.parts):
                    continue
                yield path

    def list(self) -> list[dict]:
        now = time.monotonic()
        sig = self._roots_mtime()
        if (self._cache_rows is not None
                and now - self._cache_at < CACHE_TTL
                and getattr(self, "_cache_sig", None) == sig):
            return [dict(row) for row in self._cache_rows]
        found = {}
        paths_by_name = {}
        for path in self._paths():
            try:
                meta, body = _frontmatter(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            name = (meta.get("name") or path.parent.name).strip().lower()
            if not NAME_RE.fullmatch(name):
                continue
            if name in found:
                # Earlier roots win: a bundled or user skill is never shadowed
                # by a same-named Hermes skill.
                continue
            found[name] = {"name": name, "description": meta.get("description", "")[:240],
                           "path": str(path), "chars": len(body), "source": str(path.parent.parent)}
            paths_by_name[name] = path
        ordered = sorted(found.values(), key=lambda row: row["name"])
        self._cache_rows = ordered
        self._cache_paths = paths_by_name
        self._cache_sig = sig
        self._cache_at = now
        return [dict(row) for row in ordered]

    def _find(self, name: str) -> Path:
        name = str(name or "").strip().lower()
        if not NAME_RE.fullmatch(name):
            raise ValueError("A skill name contains unsupported characters.")
        if self._cache_rows is not None and time.monotonic() - self._cache_at < CACHE_TTL:
            cached = self._cache_paths.get(name)
            if cached is not None and cached.is_file():
                return cached
        for path in self._paths():
            try:
                meta, _body = _frontmatter(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            if (meta.get("name") or path.parent.name).strip().lower() == name:
                return path
        raise KeyError(f"Unknown skill: {name}")

    @staticmethod
    def _support_files(skill_root: Path) -> list[str]:
        found = []
        for folder in ("references", "templates", "assets", "scripts"):
            root = skill_root / folder
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("*")):
                if len(found) >= 40:
                    return found
                try:
                    if path.is_file() and path.stat().st_size <= 512 * 1024:
                        found.append(path.relative_to(skill_root).as_posix())
                except OSError:
                    continue
        return found

    def view(self, name: str, file_name: str = "") -> dict:
        path = self._find(name)
        skill_root = path.parent
        meta, body = _frontmatter(path.read_text(encoding="utf-8", errors="replace"))
        if file_name:
            relative = Path(str(file_name))
            if (relative.is_absolute() or ".." in relative.parts or "\\" in str(file_name)
                    or relative.parts[0] not in ("references", "templates", "assets", "scripts")):
                raise ValueError("A skill support file must stay inside references/templates/assets/scripts.")
            target = (skill_root / relative).resolve()
            try:
                target.relative_to(skill_root.resolve())
            except ValueError:
                raise ValueError("That file is outside this skill.") from None
            try:
                if not target.is_file() or target.stat().st_size > 512 * 1024:
                    raise ValueError("That skill file is missing or too large.")
                content = target.read_text(encoding="utf-8", errors="replace")
            except OSError:
                raise ValueError("That skill file could not be read.") from None
            return {"name": str(name), "file": relative.as_posix(),
                    "content": content[:20000], "truncated": len(content) > 20000,
                    "path": str(target)}
        return {"name": str(name), "description": meta.get("description", ""),
                "meta": meta, "content": body[:20000], "path": str(path),
                "files": self._support_files(skill_root),
                "security": skill_guard.scan_skill(skill_root)}

    def scan(self, name: str) -> dict:
        path = self._find(name)
        return skill_guard.scan_skill(path.parent)

    def search(self, query: str, limit: int = 10) -> list[dict]:
        words = set(re.findall(r"[a-z0-9ąćęłńóśźż]{2,}", str(query or "").casefold()))
        if not words:
            return []
        seen = set()
        scored = []
        for path in self._paths():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            meta, body = _frontmatter(text)
            name = (meta.get("name") or path.parent.name).strip().lower()
            if not NAME_RE.fullmatch(name) or name in seen:
                continue
            seen.add(name)
            haystack = (name + " " + str(meta.get("description") or "") + " " + body).casefold()
            score = sum(haystack.count(word) for word in words)
            if score:
                scored.append((score, {"name": name,
                                       "description": str(meta.get("description") or "")[:240],
                                       "path": str(path), "chars": len(body),
                                       "source": str(path.parent.parent)}))
        scored.sort(key=lambda pair: (-pair[0], pair[1]["name"]))
        return [row | {"score": score} for score, row in scored[:max(1, min(int(limit), 30))]]
