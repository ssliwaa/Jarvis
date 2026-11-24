"""Self-modification lane ported from Brahma A-Evo, hardened for Jarvis.

Three mechanisms are kept:
  * LearnedRules   - behavioural directives stored as JSON and injected into the prompt.
  * Skill Forge    - an LLM writes a ``features/*.py`` skill, the Crucible checks it,
                     and DynamicRegistry makes it callable without a restart.
  * Auto-Heal      - a traceback OR a plain instruction is turned into a verified
                     multi-hunk source patch with a backup and a rollback record.

Design rule that changed in this version: a file is no longer simply
"protected / refused".  Every path gets a *policy level*:

  free      -> any module: edit is allowed with a syntax + compile check
  guarded   -> core runtime and tests: full verification (compile, import smoke,
               the module's own unit tests or the whole suite), automatic rollback
               on any failure, `health` probe after restart, operator confirmation
  skill     -> generated feature: edit with its stored test cases as regression
  blocked   -> non-Python files and vendored trees (config.json, .venv, .git, desktop)

Verification is fail-closed and happens *before* the write lands.  This is still a
same-user mechanism, not an OS sandbox: generated code and patches run with the
user's rights, so the HTTP endpoints keep the two-phase proposal + one-time token.
"""
from __future__ import annotations

import ast
import difflib
import hashlib
import importlib.util
import json
import os
import py_compile
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import evolution
import evolve_engine
from provider_client import DEFAULT_MODEL, ProviderError, make_client  # noqa: F401

ROOT = Path(__file__).resolve().parent
FEATURES = ROOT / "features"
STATE = Path.home() / ".jarvis-tools" / "selfmod"
RULES_PATH = STATE / "learned-rules.json"
PATCH_HISTORY = STATE / "patch-history.json"
BACKUPS = STATE / "patch-backups"
PROPOSALS = STATE / "proposals.json"
AUDIT = STATE / "audit.jsonl"
PENDING_RESTART = STATE / "pending-restart.json"
MAX_TASK = 8000
MAX_CODE = 120_000
MAX_PATCH = 120_000
MAX_EDITS = 40
MAX_SKILLS = 24
SKILL_STATS = STATE / "skill-stats.json"
QUARANTINE_AFTER = 3
WATCH_COOLDOWN = 600
MAX_SKILL_VERSIONS = 6
RUNTIME_TIMEOUT = 30.0
COMPILE_TIMEOUT = 30.0
IMPORT_TIMEOUT = 60.0
TEST_TIMEOUT = 240.0
HEALTH_URL = "http://127.0.0.1:4700/health"
LANE_LOCK = threading.RLock()

# Every mutation in this module goes through LANE_LOCK.  The HTTP server is
# threaded; two concurrent forges must not interleave features/__init__.py.

# Hard-blocked: not Python, so patching them needs a different lane.
BLOCKED_FILES = {"config.json", "requirements.txt", "package.json"}
# Guarded: edit allowed, but only through the full verification pipeline.
GUARDED_FILES = {
    "server.py", "provider_client.py", "jev_decision.py", "preflight.py", "build.py", "retrieval.py",
    "router.py", "service_control.py", "systemd_notify.py", "web_research.py",
    "browser_agent.py", "operator_tools.py", "operator_verify.py", "undo_center.py",
    "memory_store.py", "session_store.py", "skills_store.py", "mcp_client.py",
    "app_identity.py", "file_organizer.py", "documents.py", "clipboard.py",
    "briefing.py", "system_monitor.py", "scheduler.py", "operator_schedule.py",
    "self_modify.py", "tool_registry.py", "teardown.py", "tts_edge.py",
    "echo_detector.py", "browser_bay.py", "evidence_bay.py", "operator_secrets.py",
    "evolution.py", "net_guard.py", "sqlite_guard.py", "skill_guard.py",
    "context_budget.py", "context_compressor.py", "context_engine.py",
    "context_state.py", "context_tokens.py", "compression_marker.py",
    "checkpoint_manager.py", "checkpoint_pruning.py", "checkpoint_maintenance.py",
    "subagent_manager.py", "studio_routes.py", "vector_store_base.py",
    "note_vectors.py", "memory_vectors.py", "memory_extract.py", "embeddings.py",
    "stt.py", "stt_cloud.py", "web_backends.py", "web_runner.py",
    "ocr_backends.py", "ocr_runner.py", "plan_files.py", "usage_meter.py",
    "maintenance.py", "errors.py", "rea_limits.py", "teardown_brain.py",
    "agent_cli.py", "agent_consent.py", "agent_notes.py", "agent_review.py",
    "agent_router.py", "agent_team.py", "code_index.py", "desktop_tracker.py",
    "health_watchdog.py", "jarvis_remote_mcp.py", "storage_guard.py",
    "telegram_channel.py", "tts_piper.py", "vault_watcher.py",
    "visual_qa.py", "voice_bridge.py",
}
# Explicit opt-out set for root-level scratch modules (empty by default so new
# top-level Jarvis modules fail safe into `guarded` rather than `free`).
FREE_FILES: set[str] = set()
# Guarded directories (whole subtree).  `features/` is handled as "skill" and
# `tests/` as guarded, so generated work *can* be repaired instead of frozen.
# operator_modules/ are imported in-process by tool_registry; a self-mod patch
# there would bypass the sandbox, so they are manual-only.
BLOCKED_DIRS = {".venv", ".git", "artifacts", "desktop", "viewer", "node_modules",
                "__pycache__", "operator_modules"}
GUARDED_DIRS = {"tests"}

# Back-compat names: older callers read these.
PROTECTED_FILES = GUARDED_FILES
PROTECTED_DIRS = GUARDED_DIRS

# Generated skills: computation, files inside the disposable worker, formatting.
# Nothing that opens a socket, spawns a process, or evaluates source.
SAFE_IMPORTS = {
    "math", "json", "re", "datetime", "statistics", "decimal", "collections",
    "itertools", "textwrap", "hashlib", "base64", "random", "string",
    "enum", "dataclasses", "typing", "uuid", "time", "os", "os.path", "pathlib",
    "sys", "io", "csv", "logging", "unicodedata", "calendar", "zoneinfo", "copy",
    "heapq", "bisect", "numbers", "fractions", "contextlib",
    # `operator.attrgetter/methodcaller` and `functools.partial/reduce` can
    # build arbitrary callables (e.g. getattr(os, "system")) and bypass the
    # direct os-member checks; generated skills do not need them.
}
DANGEROUS_CALLS = {
    "eval", "exec", "compile", "__import__", "input", "breakpoint", "globals", "locals",
    "vars", "help",
}
DANGEROUS_ATTRS = {
    "__globals__", "__builtins__", "__subclasses__", "__class__", "__bases__",
    "__mro__", "__dict__", "__code__", "__closure__", "__reduce__", "__reduce_ex__",
    "__base__", "__init_subclass__", "__subclasshook__",
}
# `os` stays importable for paths/metadata, but these members spawn processes,
# erase files or escape the sandbox; the AST walker refuses the calls outright.
BLOCKED_OS_MEMBERS = {
    "system", "popen", "spawn", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe", "execv", "execve", "execvp",
    "execvpe", "execl", "execle", "execlp", "execlpe", "fork", "forkpty",
    "kill", "killpg", "remove", "removedirs", "unlink", "rmdir", "rename",
    "renames", "replace", "chmod", "chown", "lchmod", "lchown", "chroot",
    "symlink", "link", "mknod", "mkfifo", "truncate", "umask", "nice",
    "setuid", "seteuid", "setgid", "setegid", "setgroups", "initgroups",
    "putenv", "unsetenv", "_exit", "abort", "openpty", "dup", "dup2",
}
SAFE_DUNDER_STRINGS = {"__name__", "__doc__", "__version__", "__all__", "__main__", "__file__"}
# Names that expose the interpreter's own machinery without an attribute. A
# bare `__builtins__` Name slipped past the attribute blacklist, so
# `getattr(__builtins__, "eval")(...)` could evaluate generated code.
BLOCKED_NAMES = {"__builtins__", "builtins", "__loader__", "__spec__", "__package__"}
SECURITY_OVERRIDE = re.compile(
    r"\b(?:ignore\s+(?:all\s+)?(?:previous|safety)|bypass\s+(?:the\s+)?(?:safety|approval)|"
    r"disable\s+(?:the\s+)?(?:safety|approval)|approve\s+(?:everything|all)|"
    r"always\s+approve|send\s+(?:the\s+)?(?:secret|token|password|key)|"
    r"exfiltrat\w*|ignore\s+(?:the\s+)?system|"
    r"zawsze\s+zatwierdzaj|pomiń\s+zabezpieczenia|pomin\s+zabezpieczenia|"
    r"wyłącz\s+zabezpieczenia|wylacz\s+zabezpieczenia|wyślij\s+(?:sekret|hasło|klucz))\b", re.I)


class SelfModError(Exception):
    """A self-modification request that cannot be completed safely."""


def _atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}-{time.time_ns()}")
    temporary.write_text(text, encoding="utf-8")
    try:
        temporary.chmod(mode)
    except OSError:
        pass
    temporary.replace(path)


def audit(event: str, **fields: Any) -> None:
    """Append one line to the self-modification audit trail (never raises)."""
    row = {"ts": time.time(), "event": event}
    row.update({key: value for key, value in fields.items() if value is not None})
    try:
        STATE.mkdir(parents=True, exist_ok=True)
        with LANE_LOCK:
            with AUDIT.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False, default=str)[:4000] + "\n")
        if AUDIT.stat().st_size > 4_000_000:
            tail = AUDIT.read_text(encoding="utf-8").splitlines()[-4000:]
            _atomic_write(AUDIT, "\n".join(tail) + "\n", 0o600)
    except (OSError, ValueError):
        pass


def audit_tail(limit: int = 25) -> list[dict]:
    try:
        rows = [json.loads(line) for line in AUDIT.read_text(encoding="utf-8").splitlines()[-limit:]]
        return [row for row in rows if isinstance(row, dict)]
    except (OSError, ValueError):
        return []


def policy_for(path: Path | str, root: Path | None = None) -> str:
    """Return ``free`` | ``guarded`` | ``skill`` | ``blocked`` for a project path.

    A path outside the project root (temp fixture, external module) is ``free``:
    there is no shared policy for it, but it is still a Python file we may edit.
    """
    candidate = Path(path)
    base = Path(root or ROOT)
    try:
        relative = candidate.resolve().relative_to(base.resolve())
    except (OSError, ValueError):
        return "free" if candidate.suffix == ".py" else "blocked"
    parts = relative.parts
    if any(part in BLOCKED_DIRS for part in parts):
        return "blocked"
    if not candidate.suffix == ".py":
        return "blocked"
    if parts and parts[0] == "features":
        return "skill"
    if any(part in GUARDED_DIRS for part in parts):
        return "guarded"
    if relative.name in BLOCKED_FILES:
        return "blocked"
    if relative.name in GUARDED_FILES:
        return "guarded"
    if len(parts) == 1 and base.resolve() == ROOT.resolve() and relative.name not in FREE_FILES:
        return "guarded"
    return "free"


def _smart_source_window(source: str, instruction: str, limit: int = MAX_PATCH) -> str:
    """Return full source when <= limit, or header + AST blocks matching instruction for large files."""
    if len(source) <= limit:
        return source
    lines = source.splitlines()
    tokens = {
        tok for tok in re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}", str(instruction or "").lower())
        if tok not in {"the", "and", "for", "with", "plik", "zmien", "popraw", "dodaj", "funkcj"}
    }
    try:
        tree = ast.parse(source)
    except SyntaxError:
        half = limit // 2
        return source[:half] + "\n\n# ... [środek pliku pominięty] ...\n\n" + source[-half:]

    scored_spans: list[tuple[int, int, int]] = []
    for node in tree.body:
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", 0)
        if not start or not end:
            continue
        chunk_text = "\n".join(lines[start - 1:end])
        lower_chunk = chunk_text.lower()
        name = getattr(node, "name", "").lower()
        hits = sum((4 if tok == name else (2 if tok in name else 1)) for tok in tokens if tok in lower_chunk)
        if hits > 0:
            scored_spans.append((hits, start, end))

    if not scored_spans:
        half = limit // 2
        return source[:half] + "\n\n# ... [środek pliku pominięty] ...\n\n" + source[-half:]

    scored_spans.sort(key=lambda item: (-item[0], item[1]))
    header = "\n".join(lines[:min(90, len(lines))])
    parts = [header]
    used = len(header)
    chosen_ranges: list[tuple[int, int]] = []
    for _hits, start, end in scored_spans:
        block = "\n".join(lines[max(0, start - 3):min(len(lines), end + 2)])
        if used + len(block) + 80 > limit and chosen_ranges:
            continue
        chosen_ranges.append((max(1, start - 2), min(len(lines), end + 2)))
        used += len(block) + 40
        if used >= limit:
            break

    chosen_ranges.sort()
    for r_start, r_end in chosen_ranges:
        parts.append(f"# --- linie {r_start}..{r_end} ---\n" + "\n".join(lines[r_start - 1:r_end]))
    return ("\n\n".join(parts))[:limit]


def _json_text(value: Any, limit: int = 200_000) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)[:limit]


def _parse_json(text: str) -> Any:
    """Parse JSON even when a model wraps it in prose or a markdown fence."""
    clean = str(text or "").strip()
    if clean.startswith("```"):
        clean = re.sub(r"^```(?:json)?\s*", "", clean, flags=re.I)
        clean = re.sub(r"\s*```$", "", clean).strip()
    try:
        return json.loads(clean)
    except Exception:
        pass
    start = clean.find("{")
    if start >= 0:
        try:
            value, _ = json.JSONDecoder().raw_decode(clean[start:])
            return value
        except Exception:
            pass
    raise SelfModError("The model did not return a valid JSON object.")


def _safe_name(value: str, fallback: str = "skill") -> str:
    name = re.sub(r"[^a-z0-9_]+", "_", str(value or "").lower()).strip("_")
    if not name or not name[0].isalpha():
        name = fallback + "_" + uuid.uuid4().hex[:8]
    return name[:64]


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# --------------------------------------------------------------------------- #
# Patch engine
# --------------------------------------------------------------------------- #
class EditEngine:
    """Apply one or many ``target``/``replacement`` hunks, all-or-nothing."""

    @staticmethod
    def _locate(source: str, target: str) -> tuple[int, int]:
        if not target:
            raise SelfModError("An empty edit target cannot be located.")
        hits = source.count(target)
        if hits == 1:
            start = source.index(target)
            return start, start + len(target)
        if hits > 1:
            raise SelfModError("The edit target is not unique in the file; give more context.")
        normalized = source.replace("\r\n", "\n")
        needle = target.replace("\r\n", "\n")
        if normalized.count(needle) == 1:
            start = normalized.index(needle)
            end = start + len(needle)

            def to_source(index):
                # Map a normalized offset back onto the original CRLF text;
                # returning the normalized offset spliced the wrong bytes.
                position = count = 0
                while position < len(source) and count < index:
                    if source.startswith("\r\n", position):
                        position += 2
                    else:
                        position += 1
                    count += 1
                return position

            return to_source(start), to_source(end)
        # Last resort: match on stripped lines so indentation drift still heals.
        source_lines = source.splitlines(keepends=True)
        target_lines = [line.strip() for line in target.splitlines() if line.strip()]
        if not target_lines:
            raise SelfModError("The edit target has no non-blank line.")
        found: list[tuple[int, int]] = []
        for index in range(len(source_lines)):
            cursor, matched = index, 0
            while cursor < len(source_lines) and matched < len(target_lines):
                if not source_lines[cursor].strip():
                    cursor += 1
                    continue
                if source_lines[cursor].strip() != target_lines[matched]:
                    break
                cursor += 1
                matched += 1
            if matched == len(target_lines):
                # Record the end cursor of THIS match; a failed later attempt
                # otherwise advanced `cursor` and swallowed extra lines (bug).
                found.append((index, cursor))
        if not found:
            raise SelfModError("The model's edit target could not be matched in the file.")
        if len(found) > 1:
            raise SelfModError("The edit target matched more than one block; give more context.")
        start_index, end_index = found[0]
        start = sum(len(line) for line in source_lines[:start_index])
        end = start + sum(len(line) for line in source_lines[start_index:end_index])
        return start, end

    @classmethod
    def apply(cls, source: str, edits: list[dict]) -> str:
        if not isinstance(edits, list) or not edits:
            raise SelfModError("A patch needs at least one edit.")
        if len(edits) > MAX_EDITS:
            raise SelfModError(f"At most {MAX_EDITS} edits per patch.")
        staged = source
        for index, edit in enumerate(edits):
            if not isinstance(edit, dict):
                raise SelfModError(f"Edit {index} is not an object.")
            target, replacement = edit.get("target"), edit.get("replacement")
            if not isinstance(target, str) or not isinstance(replacement, str):
                raise SelfModError(f"Edit {index} needs target and replacement strings.")
            if len(target) > MAX_PATCH or len(replacement) > MAX_PATCH:
                raise SelfModError(f"Edit {index} is larger than {MAX_PATCH} characters.")
            start, end = cls._locate(staged, target)
            if "\r\n" in staged and "\r\n" not in replacement:
                # Keep the file's line endings when an LF-shaped hunk is
                # applied to a CRLF source; otherwise the patch creates a
                # mixed-ending file that later offsets misread.
                replacement = replacement.replace("\n", "\r\n")
            staged = staged[:start] + replacement + staged[end:]
        return staged

    @staticmethod
    def diff(path: Path, before: str, after: str, limit: int = 6000) -> str:
        return "\n".join(difflib.unified_diff(
            before.splitlines(), after.splitlines(), fromfile=str(path), tofile=str(path),
            lineterm=""))[:limit]


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
class Verification:
    """Fail-closed checks that run before a patch is allowed to land."""

    @staticmethod
    def _py(args: list[str], cwd: Path, timeout: float, readonly=None,
            stdin_text: str = "") -> tuple[int, str]:
        """Run a verification child with the live tree read-only.

        The staged file and its tests are untrusted input. Giving the child a
        writable project tree let a staged module rewrite tests (or sources)
        during verification, before any human saw the proposal. The child now
        gets a disposable HOME/TMPDIR and only that directory is writable;
        the project root is read-only.
        """
        refusal = evolution.sandbox_refusal()
        if refusal:
            return 126, refusal
        home = Path(tempfile.mkdtemp(prefix="jarvis-verify-home-"))
        try:
            environment = _runtime_environment(home)
            argv = evolution.sandbox_argv([sys.executable, *args], writable=home,
                                          readonly=readonly, cwd=cwd)
            process = subprocess.Popen(argv, cwd=str(cwd), env=environment,
                                       stdin=subprocess.PIPE if stdin_text else None,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, start_new_session=True,
                                       preexec_fn=lambda: evolution._limit_child(timeout))
            try:
                stdout, stderr = process.communicate(input=stdin_text or None, timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_group(process)
                try:
                    process.communicate(timeout=5)
                except (subprocess.TimeoutExpired, OSError):
                    pass
                return 124, f"timed out after {timeout:g}s"
            return process.returncode, ((stderr or "") + (stdout or ""))[-1500:]
        except OSError as error:
            return 125, str(error)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    @classmethod
    def run(cls, path: Path, staged: str, level: str, tests_source: str = "",
            tests_name: str = "") -> dict:
        """Return ``{"ok": bool, "steps": [...], "error": str}``; never writes the target.

        ``tests_source`` is model-generated unittest code. It is compiled and
        executed in the same read-only-project sandbox before the proposal is
        returned, instead of being written to ``tests/`` and discovered later
        with the user's full permissions.
        """
        steps: list[dict] = []

        def step(name: str, ok: bool, detail: str = "") -> bool:
            steps.append({"step": name, "ok": ok, "detail": detail[:800]})
            return ok

        try:
            ast.parse(staged, filename=str(path))
        except SyntaxError as error:
            step("syntax", False, f"line {error.lineno}: {error.msg}")
            return {"ok": False, "steps": steps, "error": f"Patch rejected: {error}"}
        step("syntax", True)

        with tempfile.TemporaryDirectory(prefix="jarvis-verify-") as directory:
            shadow = Path(directory)
            candidate = shadow / path.name
            candidate.write_text(staged, encoding="utf-8")
            try:
                py_compile.compile(str(candidate), doraise=True,
                                   cfile=str(shadow / "candidate.pyc"))
            except py_compile.PyCompileError as error:
                step("compile", False, str(error))
                return {"ok": False, "steps": steps, "error": "The patched file does not compile."}
            step("compile", True)

            # Verify the STAGED candidate, not the unpatched file still on disk:
            # a fixed prelude puts the shadow directory first on sys.path, so
            # `import {stem}` resolves the patched code while project siblings
            # and the tests package still resolve from ROOT.
            prelude = f"import sys; sys.path.insert(0, {str(shadow)!r}); "
            # A staged module that exits 0 at import made a test child look
            # successful without running a single test. The runner prints a
            # per-run sentinel only after a non-empty, successful suite.
            nonce = secrets.token_hex(12)
            marker = f"__JARVIS_VERIFY_{nonce}__"

            def test_runner(suite_expression: str) -> str:
                # Keep the nonce in a function local, not a `__main__` global:
                # a staged module can read `sys.modules['__main__'].nonce` and
                # print a forged sentinel. Read the nonce *before* importing
                # the target so it is not even set during import.
                body = "\n".join((
                    "import os, sys, unittest",
                    "nonce = sys.stdin.readline().strip()",
                    f"sys.path.insert(0, {str(shadow)!r})",
                    f"import {path.stem}",
                    "loader = unittest.TestLoader()",
                    f"suite = {suite_expression}",
                    "result = unittest.TextTestRunner(verbosity=0).run(suite)",
                    "if result.wasSuccessful() and result.testsRun:",
                    "    os.write(1, ('__JARVIS_VERIFY_' + nonce + '__').encode())",
                ))
                indented = "\n".join("    " + line for line in body.splitlines())
                return f"def __jarvis_verify__():\n{indented}\n__jarvis_verify__()\n"

            def verified(code: int, detail: str) -> bool:
                return code == 0 and marker in detail
            if level in {"guarded", "skill", "free"}:
                code, detail = cls._py(["-c", prelude + f"import {path.stem}"], ROOT,
                                       IMPORT_TIMEOUT, readonly=[str(shadow)])
                hard = code != 0 and not cls._foreign_missing(detail)
                step("import", not hard, detail)
                if hard and level == "guarded":
                    return {"ok": False, "steps": steps,
                            "error": "The patched module no longer imports."}

            test_file = ROOT / "tests" / f"test_{path.stem}.py"
            if test_file.is_file():
                runner = test_runner(f"loader.loadTestsFromName('tests.test_{path.stem}')")
                code, detail = cls._py(["-c", runner], ROOT, TEST_TIMEOUT,
                                       readonly=[str(shadow)], stdin_text=nonce + "\n")
                if not step(f"tests:{test_file.name}", verified(code, detail), detail):
                    return {"ok": False, "steps": steps,
                            "error": f"Unit tests failed: {test_file.name}"}
            elif level == "guarded":
                runner = test_runner("loader.discover('tests')")
                code, detail = cls._py(["-c", runner], ROOT, TEST_TIMEOUT,
                                       readonly=[str(shadow)], stdin_text=nonce + "\n")
                if not step("tests:suite", verified(code, detail), detail):
                    return {"ok": False, "steps": steps, "error": "The unit test suite failed."}
            else:
                step("tests", True, "no dedicated test file")

            if str(tests_source or "").strip():
                generated = shadow / f"test_{tests_name or path.stem}_generated.py"
                try:
                    compile(tests_source, str(generated), "exec")
                except SyntaxError as error:
                    return {"ok": False, "steps": steps,
                            "error": f"Generated tests do not compile: {error}"}
                generated.write_text(tests_source, encoding="utf-8")
                runner = test_runner(
                    f"loader.discover({str(shadow)!r}, pattern='test_*_generated.py')")
                code, detail = cls._py(["-c", runner], ROOT, TEST_TIMEOUT,
                                       readonly=[str(shadow)], stdin_text=nonce + "\n")
                if not step("tests:generated", verified(code, detail), detail):
                    return {"ok": False, "steps": steps,
                            "error": "Generated tests failed in the sandbox."}
            return {"ok": True, "steps": steps, "error": ""}

    @staticmethod
    def _foreign_missing(detail: str) -> bool:
        """True only for a genuinely absent *third-party* package.

        ``ModuleNotFoundError: No module named 'cv2'`` is a harmless soft pass
        on this machine; a broken first-party import (``retrieval``'s sibling
        removed by the patch) must keep failing the check.
        """
        match = re.search(r"(?:ModuleNotFoundError|ImportError):\s*No module named\s*"
                          r"'([A-Za-z0-9_.]+)'", detail or "")
        if not match:
            return False
        name = match.group(1).split(".")[0]
        return not ((ROOT / f"{name}.py").is_file() or (ROOT / name).is_dir())

    @staticmethod
    def health(timeout: float = 20.0, retries: int = 6) -> dict:
        last = "unreachable"
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(HEALTH_URL, timeout=timeout) as response:
                    if response.status == 200:
                        return {"ok": True, "attempts": attempt + 1}
            except (urllib.error.URLError, OSError, ValueError) as error:
                last = str(error)
                time.sleep(1.5)
        return {"ok": False, "attempts": retries, "error": last}


# --------------------------------------------------------------------------- #
# Proposals
# --------------------------------------------------------------------------- #
class ProposalGate:
    """Short-lived, one-time proposals: generate first, write only after apply."""

    def __init__(self, path: Path | None = None, ttl: int = 900):
        self.path = Path(path or PROPOSALS)
        self.ttl = max(60, int(ttl))

    def _rows(self) -> list[dict]:
        with LANE_LOCK:
            try:
                value = json.loads(self.path.read_text(encoding="utf-8"))
                return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []
            except (OSError, ValueError, UnicodeError):
                return []

    def _save(self, rows: list[dict]) -> None:
        with LANE_LOCK:
            _atomic_write(self.path, json.dumps(rows[-40:], ensure_ascii=False, indent=2), 0o600)

    def create(self, kind: str, payload: dict, preview: str = "") -> dict:
        now = time.time()
        proposal_id = uuid.uuid4().hex[:12]
        token = secrets.token_urlsafe(32)
        rows = [row for row in self._rows() if float(row.get("expires_at") or 0) > now]
        rows.append({"id": proposal_id, "kind": str(kind)[:30], "created_at": now,
                     "expires_at": now + self.ttl,
                     "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                     "payload": payload, "preview": str(preview)[:6000]})
        self._save(rows)
        audit("proposal", proposal=proposal_id, kind=kind,
              target=(payload or {}).get("target"), tests=(payload or {}).get("tests"))
        return {"proposal_id": proposal_id, "token": token, "expires_at": now + self.ttl,
                "preview": str(preview)[:6000], "kind": str(kind)[:30]}

    def public(self, proposal_id: str) -> dict | None:
        with LANE_LOCK:
            for row in self._rows():
                if row.get("id") == proposal_id:
                    return {key: row.get(key) for key in ("id", "kind", "created_at", "expires_at", "preview")}
        return None

    def consume(self, proposal_id: str, token: str) -> dict:
        now = time.time()
        with LANE_LOCK:
            rows = self._rows()
            for index, row in enumerate(rows):
                if row.get("id") != proposal_id:
                    continue
                if float(row.get("expires_at") or 0) <= now:
                    rows.pop(index)
                    self._save(rows)
                    audit("proposal_expired", proposal=proposal_id)
                    raise SelfModError("That self-modification proposal has expired.")
                expected = str(row.get("token_hash") or "")
                if not token or not secrets.compare_digest(expected, hashlib.sha256(token.encode()).hexdigest()):
                    raise SelfModError("That self-modification approval token is invalid.")
                rows.pop(index)
                self._save(rows)
                payload = row.get("payload")
                if not isinstance(payload, dict):
                    raise SelfModError("That proposal has no payload.")
                return payload
        raise SelfModError("That self-modification proposal is no longer available.")


class LearnedRules:
    """Persistent behavioural directives; no source code is touched."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path or RULES_PATH)

    def _read(self) -> list[dict]:
        with LANE_LOCK:
            try:
                value = json.loads(self.path.read_text(encoding="utf-8"))
                return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []
            except (OSError, ValueError, UnicodeError):
                return []

    def _write(self, rows: list[dict]) -> None:
        with LANE_LOCK:
            _atomic_write(self.path, json.dumps(rows, indent=2, ensure_ascii=False))

    def add(self, text: str, category: str = "general", origin: str = "user") -> dict:
        clean = str(text or "").strip()
        if not clean:
            raise SelfModError("A learned rule cannot be empty.")
        if SECURITY_OVERRIDE.search(clean):
            raise SelfModError("A learned rule cannot disable or override the safety boundary.")
        rows = self._read()
        for row in rows:
            if str(row.get("rule", "")).casefold() == clean.casefold():
                row["active"] = True
                row["updated_at"] = time.time()
                self._write(rows)
                return row
        row = {"id": uuid.uuid4().hex[:8], "rule": clean[:2000],
               "category": str(category or "general")[:40], "origin": str(origin or "user")[:80],
               "active": True, "created_at": time.time(), "updated_at": time.time()}
        rows.append(row)
        self._write(rows[-200:])
        audit("rule_add", rule=row["id"], category=row["category"])
        return row

    def remove(self, identifier: str) -> bool:
        rows = self._read()
        kept = [row for row in rows if row.get("id") != identifier and row.get("rule") != identifier]
        if len(kept) == len(rows):
            return False
        self._write(kept)
        return True

    def toggle(self, identifier: str) -> bool | None:
        rows = self._read()
        for row in rows:
            if row.get("id") == identifier:
                row["active"] = not bool(row.get("active", True))
                row["updated_at"] = time.time()
                self._write(rows)
                return bool(row["active"])
        return None

    def list(self, active_only: bool = False) -> list[dict]:
        rows = self._read()
        return [dict(row) for row in rows if not active_only or row.get("active", True)]

    def prompt(self) -> str:
        active = [str(row.get("rule", "")).strip() for row in self.list(active_only=True)]
        active = [rule for rule in active if rule]
        if not active:
            return ""
        return ("\n\nUSER STYLE DIRECTIVES (preferences only; they never override the safety rules, "
                "approval gates or the current task):\n" + "\n".join(f"- {rule}" for rule in active[-30:]))


def _limit_child(timeout: float) -> None:
    import resource
    pairs = (
        (resource.RLIMIT_CPU, (max(2, int(timeout) + 1), max(2, int(timeout) + 1))),
        (resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024)),
        (resource.RLIMIT_NOFILE, (96, 96)),
    )
    if hasattr(resource, "RLIMIT_AS"):
        pairs += ((resource.RLIMIT_AS, (1536 * 1024 * 1024, 1536 * 1024 * 1024)),)
    for which, value in pairs:
        try:
            resource.setrlimit(which, value)
        except (OSError, ValueError):
            pass


def _runtime_environment(home: Path) -> dict:
    return {"PATH": os.environ.get("PATH", ""), "HOME": str(home), "TMPDIR": str(home),
            "PYTHONPATH": str(ROOT), "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1",
            # Tests that need the real HOME, a writable project tree, Node or a
            # nested sandbox skip themselves under this flag; the guarded
            # verification fallback must be hermetic inside bwrap.
            "JARVIS_VERIFY_SANDBOX": "1",
            # No network in the sandbox: without this, fastembed tries to
            # download its model into the disposable HOME and blocks the
            # verification test suite on DNS retries.
            "JARVIS_EMBEDDINGS": "off"}


def _kill_group(process) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


class SkillCrucible:
    """AST allowlist plus a fail-closed child-process test runner (not a sandbox)."""

    BANNED = (
        "format c:", "format d:", "format /fs", "diskpart", "vssadmin", "bcdedit",
        "system32", "syswow64", "boot_sentry", "auto_heal_engine", "install_wizard",
        "self_modify", "rm -rf /", "mkfs.", "dd if=",
    )

    IMPORT_TO_PIP = {
        "bs4": "beautifulsoup4", "PIL": "pillow", "cv2": "opencv-python",
        "yaml": "pyyaml", "fitz": "pymupdf", "docx": "python-docx",
        "pptx": "python-pptx", "dateutil": "python-dateutil", "serial": "pyserial",
        "sklearn": "scikit-learn", "dotenv": "python-dotenv",
    }
    # Import families allowed to pull in third-party packages (installed on demand).
    INSTALLABLE = set(IMPORT_TO_PIP)

    @classmethod
    def validate_ast(cls, code: str) -> tuple[bool, str]:
        if not isinstance(code, str) or not code.strip():
            return False, "Code cannot be empty."
        try:
            tree = ast.parse(code)
        except SyntaxError as error:
            return False, f"Syntax error on line {error.lineno}: {error.msg}"
        if not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "execute"
                   for node in tree.body):
            return False, "The skill must define a top-level execute(**kwargs)."

        # Alias tracking: ``import os as o; o.system(...)`` and
        # ``from os import system`` used to bypass the os-member check, which
        # only looked for a literal ``os.system`` attribute call.
        aliases: dict[str, str] = {}
        imported_members: dict[str, tuple[str, str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    aliases[local] = alias.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                for alias in node.names:
                    if alias.name != "*":
                        imported_members[alias.asname or alias.name] = (root, alias.name)

        def root_name(value) -> str:
            while isinstance(value, (ast.Attribute, ast.Subscript)):
                value = value.value
            return aliases.get(value.id, value.id) if isinstance(value, ast.Name) else ""

        def chain_attr(value) -> set[str]:
            names = set()
            while isinstance(value, (ast.Attribute, ast.Subscript)):
                if isinstance(value, ast.Attribute):
                    names.add(value.attr)
                value = value.value
            return names

        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in BLOCKED_NAMES:
                return False, f"Blocked interpreter name: {node.id}"
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name) \
                    and node.value.id in (DANGEROUS_CALLS | {"getattr", "setattr", "delattr", "__import__"}):
                # `g = getattr; g(os, "system")` skipped the call-name checks.
                return False, f"Blocked builtin alias: {node.value.id}"
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root not in SAFE_IMPORTS and root not in cls.INSTALLABLE:
                        return False, f"Import is not allowed: {root}"
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root not in SAFE_IMPORTS and root not in cls.INSTALLABLE:
                    return False, f"Import is not allowed: {root or 'relative import'}"
            elif isinstance(node, ast.Attribute):
                if node.attr in DANGEROUS_ATTRS:
                    return False, f"Blocked attribute: {node.attr}"
                root = root_name(node.value)
                if root == "os" and node.attr in BLOCKED_OS_MEMBERS:
                    return False, f"Blocked call: os.{node.attr}"
                if root == "sys" and node.attr in {"modules", "_getframe", "settrace", "setprofile"}:
                    return False, f"Blocked sys attribute: {node.attr}"
                # sys.modules['x'].member(...) hides the real receiver behind
                # a subscript; reject any chain that traverses sys.modules.
                if root == "sys" and chain_attr(node.value) & {"modules", "_getframe"}:
                    return False, "Blocked sys.modules/_getframe access"
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    if func.id in DANGEROUS_CALLS:
                        return False, f"Blocked call: {func.id}"
                    imported = imported_members.get(func.id)
                    if imported and imported[0] == "os" and imported[1] in BLOCKED_OS_MEMBERS:
                        return False, f"Blocked call: os.{imported[1]}"
                    if func.id == "getattr":
                        target = node.args[0] if node.args else None
                        target_root = root_name(target) if target is not None else ""
                        second = node.args[1] if len(node.args) > 1 else None
                        if target_root in BLOCKED_NAMES:
                            return False, f"Blocked getattr on {target_root}"
                        if target_root in {"os", "sys"} and not isinstance(second, ast.Constant):
                            return False, "Blocked dynamic getattr on os/sys"
                        if isinstance(second, ast.Constant):
                            name = str(second.value)
                            if (name in DANGEROUS_ATTRS or name.startswith("_")) \
                                    and name not in SAFE_DUNDER_STRINGS:
                                return False, f"Blocked getattr target: {name}"
                            if target_root == "os" and name in BLOCKED_OS_MEMBERS:
                                return False, f"Blocked getattr target: os.{name}"
                            if target_root == "sys" and name in {"modules", "_getframe",
                                                                 "settrace", "setprofile"}:
                                return False, f"Blocked getattr target: sys.{name}"
                elif isinstance(func, ast.Attribute):
                    root = root_name(func.value)
                    if root == "os" and func.attr in BLOCKED_OS_MEMBERS:
                        return False, f"Blocked call: os.{func.attr}"
                    if root == "sys" and (func.attr in {"modules", "_getframe", "settrace", "setprofile"}
                                          or chain_attr(func.value) & {"modules", "_getframe"}):
                        return False, f"Blocked sys call: {func.attr}"
                    if func.attr in DANGEROUS_ATTRS:
                        return False, f"Blocked call: {func.attr}"
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                lowered = node.value.casefold()
                if lowered.startswith("__") and lowered.endswith("__") \
                        and lowered not in SAFE_DUNDER_STRINGS:
                    return False, f"Blocked dunder attribute: {lowered}"
                for banned in cls.BANNED:
                    if banned in lowered:
                        return False, f"Blocked term or path: {banned}"
        return True, ""

    @classmethod
    def dependencies(cls, code: str) -> list[str]:
        """Imports that are neither stdlib-safe nor obviously packaged yet."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root not in SAFE_IMPORTS:
                        found.add(root)
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root not in SAFE_IMPORTS:
                    found.add(root)
            elif isinstance(node, ast.ImportFrom) and not node.module:
                found.add("<relative>")
        return sorted(found)

    @classmethod
    def install_dependencies(cls, dependencies: list[str], allow: bool = False) -> str:
        if not dependencies:
            return "No external dependencies."
        if not allow:
            raise SelfModError("Missing dependencies: " + ", ".join(dependencies) +
                               ". Install them or retry in full mode.")
        installed = []
        for dependency in dependencies:
            if dependency == "<relative>":
                continue
            package = cls.IMPORT_TO_PIP.get(dependency, dependency)
            if importlib.util.find_spec(dependency) is not None:
                continue
            result = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", package],
                                    capture_output=True, text=True, timeout=240)
            if result.returncode != 0:
                raise SelfModError(f"Could not install {package}: {(result.stderr or result.stdout)[:220]}")
            installed.append(package)
        return "Installed: " + ", ".join(installed) if installed else "Dependencies already present."

    @classmethod
    def test(cls, code: str, cases: list[dict] | None = None, timeout: float = 75.0) -> dict:
        """Run generated code in a separate process and fail closed.

        A test case must contain an assertion (``expect``, ``expect_contains``
        or ``expect_error``).  Missing JSON output is a failure, never a pass.
        """
        cases = cases or []
        refusal = evolution.sandbox_refusal()
        if refusal:
            return {"ok": False, "error": refusal, "results": []}
        if not isinstance(cases, list) or not cases:
            return {"ok": False, "error": "At least one test case is required.", "results": []}
        for index, case in enumerate(cases):
            if (not isinstance(case, dict) or not isinstance(case.get("input", {}), dict)
                    or not any(key in case for key in ("expect", "expect_contains", "expect_error"))):
                return {"ok": False, "results": [],
                        "error": f"Test case {index} needs input and an assertion."}
        # The generated module is imported by a trusted harness; it is not
        # spliced into the harness source. The harness reads a per-run nonce
        # from stdin *before* importing the module, catches BaseException
        # (including SystemExit) and always prints the real verdict last.
        harness = r"""
import asyncio, importlib.util, inspect, json, os, resource, sys, traceback

nonce = sys.stdin.readline().strip()
if not nonce:
    raise SystemExit(2)
for which, value in (
    (resource.RLIMIT_CPU, (max(2, int(__TIMEOUT__) + 1),) * 2),
    (resource.RLIMIT_FSIZE, (16 * 1024 * 1024,) * 2),
    (resource.RLIMIT_NOFILE, (96,) * 2),
):
    try:
        resource.setrlimit(which, value)
    except (OSError, ValueError):
        pass
if hasattr(resource, "RLIMIT_AS"):
    try:
        resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024 * 1024,) * 2)
    except (OSError, ValueError):
        pass

rows, load_error = [], ""
try:
    cases = json.load(open(sys.argv[2], encoding="utf-8"))
except Exception as exc:
    print("__JARVIS_RESULT_" + nonce + "__" + json.dumps(
        {"ok": False, "error": "cases: " + str(exc)[:300], "results": []}))
    raise SystemExit(0)
try:
    spec = importlib.util.spec_from_file_location("jarvis_skill", sys.argv[1])
    module = importlib.util.module_from_spec(spec)
    sys.modules["jarvis_skill"] = module
    spec.loader.exec_module(module)
    execute = getattr(module, "execute", None)
    if not callable(execute):
        load_error = "the module does not define a callable execute"
except BaseException as exc:
    load_error = "import: " + (str(exc) or type(exc).__name__)[:500]
if not load_error:
    for index, case in enumerate(cases):
        args = case.get("input") or {}
        try:
            result = asyncio.run(execute(**args)) if inspect.iscoroutinefunction(execute) else execute(**args)
        except BaseException as exc:
            if "expect_error" in case:
                rows.append({"index": index, "success": True, "output": "<expected error>"})
            else:
                rows.append({"index": index, "success": False, "error": str(exc)[:500],
                             "traceback": traceback.format_exc()[-1200:]})
            continue
        if isinstance(result, dict) and (result.get("error") or result.get("success") is False):
            rows.append({"index": index, "success": False,
                         "error": str(result.get("error") or result.get("message") or "result reported failure")})
            continue
        if "expect_error" in case:
            rows.append({"index": index, "success": False, "error": "expected an exception"})
            continue
        if "expect" in case:
            if result != case["expect"]:
                rows.append({"index": index, "success": False,
                             "error": "result != expected", "output": str(result)[:700]})
                continue
        elif "expect_contains" in case:
            if str(case["expect_contains"]) not in str(result):
                rows.append({"index": index, "success": False,
                             "error": "expected substring was absent", "output": str(result)[:700]})
                continue
        else:
            rows.append({"index": index, "success": False, "error": "no assertion"})
            continue
        try:
            encoded = json.dumps(result, ensure_ascii=False, default=str)
        except Exception:
            rows.append({"index": index, "success": False, "error": "result is not JSON-serialisable"})
            continue
        rows.append({"index": index, "success": True, "output": encoded[:700]})
payload = {"ok": not load_error and len(rows) == len(cases) and all(row["success"] for row in rows),
           "results": rows}
if load_error:
    payload["error"] = load_error
print("__JARVIS_RESULT_" + nonce + "__" + json.dumps(payload))
""".replace("__TIMEOUT__", str(int(max(2, timeout))))
        runtime = Path(tempfile.mkdtemp(prefix="jarvis-selfmod-test-"))
        started = time.time()
        nonce = secrets.token_hex(16)
        try:
            (runtime / "skill.py").write_text(code, encoding="utf-8")
            (runtime / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
            process = subprocess.Popen(
                evolution.sandbox_argv([sys.executable, "-c", harness,
                                        str(runtime / "skill.py"),
                                        str(runtime / "cases.json")],
                                       writable=runtime, cwd=runtime),
                cwd=str(runtime), env=_runtime_environment(runtime), text=True,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, preexec_fn=lambda: evolution._limit_child(timeout))
            try:
                stdout, stderr = process.communicate(input=nonce + "\n", timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_group(process)
                try:
                    process.communicate(timeout=5)
                except (subprocess.TimeoutExpired, OSError):
                    pass
                return {"ok": False, "error": f"Test timed out after {timeout:g}s.", "elapsed": timeout}
        finally:
            shutil.rmtree(runtime, ignore_errors=True)
        elapsed = round(time.time() - started, 2)
        marker = "__JARVIS_RESULT_" + nonce + "__"
        if process.returncode != 0:
            return {"ok": False, "error": (stderr or stdout or "test process failed")[-900:],
                    "elapsed": elapsed}
        payload = None
        for line in reversed((stdout or "").splitlines()):
            if line.startswith(marker):
                try:
                    payload = json.loads(line[len(marker):])
                except ValueError:
                    payload = None
                break
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            return {"ok": False, "error": "Test process returned no trusted JSON result.",
                    "elapsed": elapsed, "results": []}
        if len(payload["results"]) != len(cases):
            return {"ok": False, "error": "Test process did not report every case.",
                    "elapsed": elapsed, "results": payload["results"]}
        failures = [row for row in payload["results"] if not row.get("success")]
        return {"ok": bool(payload.get("ok")) and not failures, "results": payload["results"],
                "error": (payload.get("error") or
                          (failures[0].get("error", "test failed") if failures else "")),
                "elapsed": elapsed}


def _run_feature(path: Path, arguments: dict, timeout: float = RUNTIME_TIMEOUT) -> Any:
    """Execute a generated skill in a disposable child process, not in server.py."""
    if not isinstance(arguments, dict) or len(json.dumps(arguments, ensure_ascii=False)) > 16_384:
        raise SelfModError("Skill arguments must be a JSON object under 16 KB.")
    refusal = evolution.sandbox_refusal()
    if refusal:
        raise SelfModError(refusal)
    harness = r"""
import asyncio, importlib.util, inspect, json, sys, traceback
data = json.loads(sys.stdin.read())
path, arguments = data["path"], data["arguments"]
try:
    spec = importlib.util.spec_from_file_location("jarvis_generated_skill", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load generated skill")
    module = importlib.util.module_from_spec(spec)
    sys.modules["jarvis_generated_skill"] = module
    spec.loader.exec_module(module)
    function = getattr(module, "execute", None)
    if not callable(function):
        raise RuntimeError("generated skill has no execute function")
    result = asyncio.run(function(**arguments)) if inspect.iscoroutinefunction(function) else function(**arguments)
    print("__JARVIS_RESULT__" + json.dumps({"ok": True, "result": result}, ensure_ascii=False, default=str))
except Exception as exc:
    print("__JARVIS_RESULT__" + json.dumps({"ok": False, "error": str(exc)[:800],
        "traceback": traceback.format_exc()[-1200:]}, ensure_ascii=False))
"""
    runtime = Path(tempfile.mkdtemp(prefix="jarvis-selfmod-run-"))
    process = None
    stdout, stderr = "", ""
    try:
        process = subprocess.Popen(
                                   evolution.sandbox_argv([sys.executable, "-c", harness], writable=runtime,
                                                          readonly=[str(path.parent)]),
                                   cwd=str(runtime), env=_runtime_environment(runtime), text=True,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, preexec_fn=lambda: _limit_child(timeout))
        try:
            stdout, stderr = process.communicate(json.dumps({"path": str(path), "arguments": arguments}),
                                                 timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_group(process)
            process.communicate()
            raise SelfModError(f"Skill timed out after {timeout:g}s.") from None
    finally:
        shutil.rmtree(runtime, ignore_errors=True)
    for line in reversed((stdout or "").splitlines()):
        if line.startswith("__JARVIS_RESULT__"):
            try:
                payload = json.loads(line[len("__JARVIS_RESULT__"):])
            except ValueError:
                payload = None
            if isinstance(payload, dict) and payload.get("ok") is True:
                return payload.get("result")
            if isinstance(payload, dict):
                raise SelfModError(str(payload.get("error") or "generated skill failed"))
            break
    raise SelfModError((stderr or stdout or "generated skill returned no result")[-900:])


def _skill_stats() -> dict:
    try:
        value = json.loads(SKILL_STATS.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, UnicodeError):
        return {}


def _write_skill_stats(rows: dict) -> None:
    _atomic_write(SKILL_STATS, json.dumps(rows, indent=2, sort_keys=True))


class DynamicSkill:
    def __init__(self, registry: "DynamicRegistry", name: str, path: Path, metadata: dict):
        self.registry = registry
        self.name = name
        self.path = path
        self.metadata = metadata
        self.description = str(metadata.get("description") or f"Generated skill {name}.")
        self.parameters = metadata.get("parameters") or {"type": "object", "properties": {}}
        self.module = None

    def declaration(self) -> dict:
        return {"name": self.name, "description": self.description[:1200],
                "input_schema": normalize_schema(self.parameters)}

    def execute(self, arguments: dict) -> Any:
        # Never import generated code into the server process.  A skill that
        # calls os._exit() must kill only its disposable worker.
        try:
            result = _run_feature(self.path, arguments)
        except SelfModError as error:
            self.stats(failure=str(error)[:300])
            raise
        self.stats(ok=True)
        return result

    def stats(self, ok: bool = False, failure: str = "") -> dict:
        with LANE_LOCK:
            rows = _skill_stats()
            row = rows.get(self.name) or {"runs": 0, "failures": 0, "quarantined": False}
            row["runs"] = int(row.get("runs", 0)) + 1
            if not ok:
                row["failures"] = int(row.get("failures", 0)) + 1
                row["last_error"] = failure[:300]
                if row["failures"] >= QUARANTINE_AFTER:
                    row["quarantined"] = True
            rows[self.name] = row
            _write_skill_stats(rows)
            return row


def normalize_schema(value: Any) -> dict:
    """Accept Brahma's Gemini-style OBJECT schema and return JSON Schema."""
    if not isinstance(value, dict):
        return {"type": "object", "properties": {}}
    out = {}
    for key, item in value.items():
        if key == "type" and isinstance(item, str):
            out[key] = item.lower()
        elif key in {"properties", "items"}:
            if key == "properties" and isinstance(item, dict):
                out[key] = {str(k): normalize_schema(v) for k, v in item.items()}
            elif isinstance(item, dict):
                out[key] = normalize_schema(item)
            else:
                out[key] = item
        elif isinstance(item, (dict, list)):
            out[key] = normalize_schema(item) if isinstance(item, dict) else item
        else:
            out[key] = item
    if out.get("type") == "object" and "properties" not in out:
        out["properties"] = {}
    return out


class DynamicRegistry:
    def __init__(self, features_dir: Path | None = None):
        self.features_dir = Path(features_dir or FEATURES)
        self.skills: dict[str, DynamicSkill] = {}
        self.aliases: dict[str, str] = {}
        self.errors: list[str] = []
        self.refresh()

    def refresh(self) -> int:
        with LANE_LOCK:
            return self._refresh_locked()

    def _refresh_locked(self) -> int:
        self.skills.clear()
        self.aliases.clear()
        self.errors.clear()
        self.features_dir.mkdir(parents=True, exist_ok=True)
        for path in sorted(self.features_dir.glob("*.py")):
            if path.name.startswith("_") or path.name == "__init__.py":
                continue
            try:
                metadata = self._metadata_file(path)
                if metadata is not None:
                    self._add(path.stem, path, metadata)
            except Exception as error:
                self.errors.append(f"{path.name}: {type(error).__name__}")
        for directory in sorted(self.features_dir.iterdir()):
            if not directory.is_dir() or directory.name.startswith((".", "_")):
                continue
            manifest_path = directory / "manifest.json"
            code_path = directory / "skill.py"
            if manifest_path.is_file() and code_path.is_file():
                try:
                    metadata = json.loads(manifest_path.read_text(encoding="utf-8"))
                    self._add(str(metadata.get("name") or directory.name), code_path, metadata)
                except Exception as error:
                    self.errors.append(f"{directory.name}: {type(error).__name__}")
        return len(self.skills)

    @staticmethod
    def _metadata_file(path: Path) -> dict | None:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            return None
        for node in tree.body:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
            if any(isinstance(target, ast.Name) and target.id == "FEATURE_METADATA" for target in targets):
                try:
                    value = ast.literal_eval(node.value)
                    if isinstance(value, dict):
                        return value
                except Exception:
                    return None
        doc = ast.get_docstring(tree)
        return {"name": path.stem, "description": doc or f"Generated skill {path.stem}.",
                "parameters": {"type": "object", "properties": {}}}

    def _add(self, name: str, path: Path, metadata: dict) -> None:
        clean = _safe_name(name)
        if clean in self.skills:
            return
        skill = DynamicSkill(self, clean, path, metadata)
        self.skills[clean] = skill
        for alias in metadata.get("aliases") or []:
            alias_name = _safe_name(str(alias))
            if alias_name and alias_name not in self.skills:
                self.aliases[alias_name] = clean

    def rank(self, query: str = "") -> list[DynamicSkill]:
        """Relevance order for a task string; original order when the query is empty."""
        quarantined = {name for name, row in _skill_stats().items() if row.get("quarantined")}
        skills = [skill for skill in self.skills.values() if skill.name not in quarantined]
        tokens = {token for token in re.split(r"[^a-z0-9_]+", str(query).casefold()) if len(token) > 2}
        if not tokens:
            return skills
        def weight(skill: DynamicSkill) -> int:
            haystack = " ".join([skill.name, skill.description,
                                 " ".join(map(str, (skill.metadata.get("triggers") or [])))]).casefold()
            return sum(2 if token in skill.name else 1 for token in tokens if token in haystack)
        return sorted(skills, key=weight, reverse=True)

    def declarations(self, existing: set[str] | None = None, query: str = "") -> list[dict]:
        existing = existing or set()
        return [skill.declaration() for skill in self.rank(query)[:MAX_SKILLS]
                if skill.name not in existing]

    def has(self, name: str) -> bool:
        return name in self.skills or name in self.aliases

    def get(self, name: str) -> DynamicSkill | None:
        return self.skills.get(name) or self.skills.get(self.aliases.get(name, ""))

    def run(self, name: str, arguments: dict) -> Any:
        skill = self.get(name)
        if skill is None:
            raise SelfModError(f"No active skill named {name!r}.")
        return skill.execute(arguments)

    def stats(self) -> dict:
        return _skill_stats()

    def reset_stats(self, name: str = "") -> dict:
        with LANE_LOCK:
            rows = _skill_stats()
            if name:
                rows.pop(name, None)
            else:
                rows.clear()
            _write_skill_stats(rows)
            return rows

    def list(self) -> list[dict]:
        stats = _skill_stats()
        return [{"name": skill.name, "description": skill.description, "path": str(skill.path),
                 "runs": (stats.get(skill.name) or {}).get("runs", 0),
                 "failures": (stats.get(skill.name) or {}).get("failures", 0),
                 "quarantined": bool((stats.get(skill.name) or {}).get("quarantined")),
                 "aliases": [alias for alias, target in self.aliases.items() if target == skill.name]}
                for skill in self.skills.values()]


class SkillForge:
    """LLM -> Crucible -> features/ -> DynamicRegistry.  Existing skills upgrade in place."""

    SYSTEM = """You are Jarvis Skill Forge. Create or upgrade one self-contained Python skill.
Return ONLY JSON:
{"manifest":{"name":"snake_case","description":"when to use it","aliases":[],"triggers":[],
 "parameters":{"type":"object","properties":{}}},"code":"full Python source","test_cases":[{"input":{},"expect":"value"}]}
Rules:
- define a top-level execute(**kwargs); handle empty kwargs with safe defaults
- cover the happy path AND at least one edge case (empty input, wrong type, boundary)
- use only the standard library unless a dependency is genuinely necessary
- files may be read and written with open()/pathlib; the worker has a throwaway HOME
- never print, request or hardcode secrets; never disable TLS verification
- return a useful string or JSON-serialisable dict; never return {"error": ...} on ordinary failure
- every test case must include input and expect, expect_contains or expect_error
- no subprocess, socket, urllib, requests, ctypes, eval or exec
"""

    REPAIR = """Repair this generated Jarvis skill. Return ONLY JSON: {{"code":"full corrected Python source"}}.
The skill failed validation or its child-process tests. Preserve execute(**kwargs), safe defaults and no secrets.
Validation error: {error}
Goal: {goal}
Broken code:
```python
{code}
```
"""

    def __init__(self, client, model: str, registry: DynamicRegistry, allow_install: bool = False):
        self.client = client
        self.model = str(model or DEFAULT_MODEL)
        self.registry = registry
        self.allow_install = bool(allow_install)

    def _text(self, prompt: str, system: str, max_tokens: int = 6000) -> str:
        if self.client is None:
            raise SelfModError("Skill Forge needs a model client.")
        response = self.client.messages.create(
            model=self.model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": prompt}], stream=False)
        return "\n".join(str(getattr(block, "text", "")) for block in response.content
                         if getattr(block, "type", "") == "text").strip()

    def forge(self, goal: str, name: str = "", context: str = "") -> dict:
        package = self._build(goal, name, context)
        feature_path = self._write(package)
        self.registry.refresh()
        return {"ok": True, "name": package["name"], "path": str(feature_path),
                "description": str(package["manifest"].get("description") or ""),
                "tests": package["tests"], "declarations": self.registry.declarations()}

    def propose(self, goal: str, name: str = "", context: str = "") -> dict:
        """Generate and test, but do not write. Apply with ProposalGate + token."""
        package = self._build(goal, name, context)
        preview = (f"Skill: {package['name']}  (target: {package['target_name']})\n"
                   f"Description: {package['manifest'].get('description', '')}\n"
                   f"Tests: {len(package['tests'].get('results', []))} passed\n"
                   f"Code hash: {_sha(package['code'])}\n"
                   f"Upgrade of an existing skill: {'yes' if package['upgrade'] else 'no'}\n")
        if package["upgrade"]:
            preview += "\n--- diff vs current version ---\n" + package["diff"]
        else:
            preview += "\n--- code ---\n" + package["code"][:3000]
        return {"kind": "skill", "payload": package, "preview": preview}

    def apply_package(self, package: dict) -> dict:
        if (not isinstance(package, dict) or not isinstance(package.get("code"), str)
                or not isinstance(package.get("cases"), list) or not package["cases"]):
            raise SelfModError("A skill proposal is malformed.")
        valid, error = SkillCrucible.validate_ast(package["code"])
        if not valid:
            raise SelfModError(error)
        feature_path = self._write(package)
        self.registry.refresh()
        audit("skill_apply", name=package.get("name"), path=str(feature_path),
              upgrade=bool(package.get("upgrade")))
        return {"ok": True, "name": package.get("name"), "path": str(feature_path),
                "description": str(package.get("manifest", {}).get("description") or ""),
                "tests": package.get("tests", {}), "declarations": self.registry.declarations()}

    def _build(self, goal: str, name: str = "", context: str = "") -> dict:
        goal = str(goal or "").strip()
        if not 3 <= len(goal) <= MAX_TASK:
            raise SelfModError("A goal of 3 to 8,000 characters is required.")
        existing = self.registry.get(_safe_name(name)) if name else None
        if existing is not None:
            context = (f"The skill {existing.name} already exists and must be improved, "
                       f"keeping the same name and every currently passing behaviour.\n"
                       f"Current source:\n```python\n{existing.path.read_text(encoding='utf-8')[:40_000]}\n```\n"
                       + context)
        raw = self._text(f"Goal: {goal}\nPreferred name: {name or 'auto'}\nContext: {context}", self.SYSTEM)
        package = _parse_json(raw)
        manifest = package.get("manifest")
        code = package.get("code")
        cases = package.get("test_cases")
        if not isinstance(cases, list) or not cases:
            raise SelfModError("Skill Forge must provide at least one test case with an assertion.")
        if not isinstance(manifest, dict) or not isinstance(code, str):
            raise SelfModError("The model returned no manifest/code pair.")
        skill_name = _safe_name(str(manifest.get("name") or name or "skill"))
        upgrade = skill_name in self.registry.skills
        if len(code) > MAX_CODE:
            raise SelfModError("Generated code is too large.")
        error = ""
        tested: dict = {}
        for attempt in range(3):
            valid, error = SkillCrucible.validate_ast(code)
            if not valid and attempt < 2:
                code = self._repair(code, error, goal)
                continue
            if not valid:
                raise SelfModError(error)
            dependencies = SkillCrucible.dependencies(code)
            if dependencies:
                SkillCrucible.install_dependencies(dependencies, self.allow_install)
            # Regression first: an upgrade must not break the behaviour it already has.
            if upgrade:
                # Regression only for inputs the upgrade did not deliberately redefine.
                redefined = {json.dumps(case.get("input") or {}, sort_keys=True) for case in cases}
                previous = [case for case in self._previous_cases(skill_name)
                            if json.dumps(case.get("input") or {}, sort_keys=True) not in redefined]
                if previous:
                    regression = SkillCrucible.test(code, previous)
                    if not regression.get("ok"):
                        error = "regression on existing test cases: " + str(regression.get("error"))
                        if attempt < 2:
                            code = self._repair(code, error, goal)
                            continue
                        raise SelfModError(error)
            tested = SkillCrucible.test(code, cases)
            if tested.get("ok"):
                break
            error = str(tested.get("error") or "Crucible test failed")
            if attempt < 2:
                code = self._repair(code, error, goal)
        else:
            raise SelfModError(f"Crucible rejected the skill: {error}")
        diff = ""
        if upgrade:
            package_dir = self.registry.features_dir / skill_name / "skill.py"
            if package_dir.is_file():
                diff = EditEngine.diff(package_dir, package_dir.read_text(encoding="utf-8"), code)
        return {"name": skill_name, "target_name": skill_name, "manifest": manifest, "code": code,
                "cases": cases, "tests": tested, "upgrade": upgrade, "diff": diff}

    def _previous_cases(self, name: str) -> list[dict]:
        path = self.registry.features_dir / name / "test_cases.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return [row for row in value if isinstance(row, dict)][:20] if isinstance(value, list) else []
        except (OSError, ValueError, UnicodeError):
            return []

    def _repair(self, code: str, error: str, goal: str) -> str:
        response = self._text(self.REPAIR.format(error=error[:1200], goal=goal[:1000], code=code[:MAX_CODE]),
                              "Repair generated Python. Return strict JSON.", max_tokens=6000)
        repaired = _parse_json(response).get("code")
        if not isinstance(repaired, str):
            raise SelfModError("The repair response contained no code.")
        audit("skill_repair", error=error[:200])
        return repaired

    def _version_paths(self, name: str) -> tuple[Path, Path, Path]:
        features = self.registry.features_dir
        target, package = features / f"{name}.py", features / name
        if not target.exists() and not package.exists():
            return target, package, target
        for index in range(2, MAX_SKILL_VERSIONS + 1):
            versioned = f"{name}_v{index}"
            candidate = features / f"{versioned}.py"
            if not candidate.exists():
                return features / f"{versioned}.py", features / versioned, target
        raise SelfModError(f"{name} already has {MAX_SKILL_VERSIONS} versions; clean some up.")

    def _write(self, package: dict) -> Path:
        name = _safe_name(str(package.get("name") or "skill"))
        with LANE_LOCK:
            features = self.registry.features_dir
            features.mkdir(parents=True, exist_ok=True)
            target, directory = features / f"{name}.py", features / name
            if package.get("upgrade") and target.is_file():
                stamp = time.strftime("%Y%m%d-%H%M%S")
                # `.py.bak` suffix: Path.glob("*.py") matches dotted files, so a
                # plain `.name.stamp.py` backup was re-imported as a phantom skill.
                backup = features / ".versions" / f"{name}.{stamp}.py.bak"
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, backup)
                package["previous_source"] = target.read_text(encoding="utf-8")
                package["backup"] = str(backup)
            elif target.exists() or directory.exists():
                target, directory, _ = self._version_paths(name)
                name = target.stem
            return self._write_locked(name, package["manifest"], package["code"],
                                      package["cases"], target, directory)

    def _write_locked(self, name: str, manifest: dict, code: str, cases: list,
                      target: Path, package: Path) -> Path:
        metadata = {"name": _safe_name(name), "description": str(manifest.get("description") or ""),
                    "aliases": list(manifest.get("aliases") or [])[:20],
                    "parameters": normalize_schema(manifest.get("parameters") or {}),
                    "updated_at": time.time()}
        header = '"""Generated by Jarvis Skill Forge."""\nFEATURE_METADATA = ' + repr(metadata) + "\n\n"
        if "FEATURE_METADATA" not in code:
            code = header + code
        _atomic_write(target, code, 0o700)
        _atomic_write(package / "manifest.json", json.dumps(metadata, indent=2), 0o600)
        _atomic_write(package / "skill.py", code, 0o700)
        _atomic_write(package / "test_cases.json", json.dumps(cases, indent=2), 0o600)
        init = self.registry.features_dir / "__init__.py"
        existing = init.read_text(encoding="utf-8") if init.is_file() else ""
        line = f"from . import {target.stem}\n"
        if line not in existing:
            _atomic_write(init, existing + line, 0o600)
        return target


class AutoHeal:
    """Traceback or instruction -> verified multi-hunk patch -> backup -> rollback."""

    SYSTEM = """You repair one Python file of a local assistant. Return ONLY JSON:
{"explanation":"one sentence","edits":[{"target":"exact source substring","replacement":"replacement"}]}
Rules:
- the smallest set of edits that makes the failure impossible; usually one edit, never cosmetic churn
- every target must occur exactly once; include whole lines with their indentation
- keep the public API, imports and style of the file; no new network calls, secrets or subprocesses
- if the real fix belongs in another function, still return only edits for THIS file
"""

    CHANGE = """Change one Python file of a local assistant as described. Return ONLY JSON:
{"explanation":"one sentence","edits":[{"target":"exact source substring","replacement":"replacement"}],
 "new_tests":"optional full unittest module source"}
Rules:
- every target must occur exactly once; include whole lines and their indentation
- keep the existing public API unless the instruction says otherwise
- stay inside the file's style; no new third-party dependencies
- add or extend a unit test in new_tests when the behaviour is observable
"""

    def __init__(self, client, model: str, root: Path | None = None,
                 history: Path | None = None, backups: Path | None = None):
        self.client = client
        self.model = str(model or DEFAULT_MODEL)
        self.root = Path(root or ROOT).resolve()
        self.history_path = Path(history or PATCH_HISTORY)
        self.backups = Path(backups or BACKUPS)

    def _history(self) -> list[dict]:
        try:
            value = json.loads(self.history_path.read_text(encoding="utf-8"))
            return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []
        except (OSError, ValueError, UnicodeError):
            return []

    def _save_history(self, rows: list[dict]) -> None:
        _atomic_write(self.history_path, json.dumps(rows[-200:], indent=2, ensure_ascii=False))

    def history(self) -> list[dict]:
        return list(reversed(self._history()))[:20]

    def parse(self, traceback_text: str) -> dict:
        text = str(traceback_text or "")
        if not text.strip():
            raise SelfModError("A traceback or error text is required.")
        lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
        last = lines[-1] if lines else ""
        kind, _, message = last.partition(":")
        matches = re.findall(r'File\s+["\']([^"\']+\.py)["\'],\s+line\s+(\d+)', text)
        for raw_path, line_text in reversed(matches):
            if "site-packages" in raw_path or "/.venv/" in raw_path or "\\Lib\\" in raw_path:
                continue
            candidate = Path(raw_path)
            if not candidate.is_absolute():
                candidate = self.root / candidate
            try:
                resolved = candidate.resolve()
                relative = resolved.relative_to(self.root)
            except (OSError, ValueError):
                continue
            level = policy_for(resolved, self.root)
            if level == "blocked":
                raise SelfModError(f"{relative} is blocked from auto-healing.")
            return {"success": True, "file": str(resolved), "line": int(line_text),
                    "level": level, "relative": str(relative),
                    "exception": kind.strip() or "Exception", "message": message.strip()}
        raise SelfModError("No first-party .py file was found in the traceback.")

    def _context(self, source: str, line_number: int) -> str:
        lines = source.splitlines()
        start, end = max(0, line_number - 60), min(len(lines), line_number + 60)
        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    begin = getattr(node, "lineno", 1) - 1
                    finish = getattr(node, "end_lineno", begin + 1)
                    if begin <= line_number - 1 <= finish and (finish - begin) <= 220:
                        start, end = begin, finish
                        break
        except SyntaxError:
            pass
        return "\n".join(lines[start:end])

    def _ask(self, prompt: str, system: str, max_tokens: int = 6000) -> dict:
        if self.client is None:
            raise SelfModError("Auto-Heal needs a model client.")
        response = self.client.messages.create(
            model=self.model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": prompt}], stream=False)
        text = "\n".join(str(getattr(block, "text", "")) for block in response.content
                         if getattr(block, "type", "") == "text")
        value = _parse_json(text)
        edits = value.get("edits")
        if not isinstance(edits, list) or not edits:
            # Tolerate the single-chunk shape older prompts produced.
            if isinstance(value.get("target_chunk"), str):
                edits = [{"target": value.get("target_chunk"),
                          "replacement": value.get("replacement_chunk")}]
            else:
                raise SelfModError("The patch response has no edits.")
        return {"explanation": str(value.get("explanation") or "Targeted fix.")[:500],
                "edits": edits, "new_tests": value.get("new_tests") if isinstance(value.get("new_tests"), str) else ""}

    def review(self, target_path: Path, source: str, staged: str, instruction: str) -> dict:
        """Second opinion from a fresh context before anything is written.

        This gate fails closed: an unavailable reviewer or an unparsable answer
        is a rejection, not a silent approval.
        """
        if self.client is None:
            return {"ok": False, "skipped": True,
                    "reasons": ["the reviewer is unavailable; refusing an unreviewed patch"]}
        diff = EditEngine.diff(target_path, source, staged, limit=24_000)
        prompt = f"Instruction: {instruction[:1500]}\n\n--- diff ---\n{diff}"
        critic_model = (
            os.environ.get("JARVIS_SELFMOD_CRITIC_MODEL", "").strip()
            or getattr(self, "critic_model", "")
            or self.model
        )
        try:
            response = self.client.messages.create(
                model=critic_model, max_tokens=800, system=evolution.PromptLab().get("critic"),
                messages=[{"role": "user", "content": prompt}], stream=False)
            text = "\n".join(str(getattr(block, "text", "")) for block in response.content
                              if getattr(block, "type", "") == "text")
            value = _parse_json(text)
        except (SelfModError, ProviderError) as error:
            return {"ok": False, "skipped": False,
                    "reasons": ["the reviewer failed: " + str(error)[:200]]}
        raw = value.get("reasons") or []
        reasons = [str(item)[:200] for item in raw if item][:5]
        approve = value.get("approve") is True
        if not approve and not reasons:
            reasons = ["the review rejected the patch without stating a reason"]
        audit("critic", target=str(target_path), approve=approve, model=critic_model)
        return {"ok": approve, "reasons": reasons, "skipped": False}

    def _stage(self, target_path: Path, source: str, patch: dict, level: str,
               proposal_kind: str = "heal", disk_source: str | None = None) -> dict:
        staged = EditEngine.apply(source, patch["edits"])
        live_source = source if disk_source is None else disk_source
        if staged == live_source:
            raise SelfModError("The proposed patch does not change the file.")
        blocks_ok, block_err = evolve_engine.EvolveBlocks.verify_frozen_outside_blocks(source, staged)
        if not blocks_ok:
            try:
                evolution.Failures().add(target_path.stem, block_err, kind="evolve_block")
            except evolution.EvolutionError:
                pass
            raise SelfModError(block_err)
        review = self.review(target_path, live_source, staged, str(patch.get("exception") or ""))
        if not review["ok"]:
            try:
                evolution.Failures().add(target_path.stem,
                                         "Review rejected the patch: " + "; ".join(review["reasons"])[:500],
                                         kind="reviewed")
            except evolution.EvolutionError:
                pass
            raise SelfModError("Review rejected the patch: " + "; ".join(review["reasons"]))
        tests_path, tests_source = None, patch.get("new_tests") or ""
        if tests_source.strip():
            tests_path = self.root / "tests" / f"test_{target_path.stem}_selfmod.py"
            try:
                compile(tests_source, str(tests_path), "exec")
            except SyntaxError as error:
                raise SelfModError(f"The generated tests do not compile: {error}") from None
        verification = Verification.run(target_path, staged, level, tests_source=tests_source,
                                        tests_name=target_path.stem)
        if not verification["ok"]:
            audit("heal_rejected", target=str(target_path), error=verification["error"])
            try:
                evolution.Failures().add(target_path.stem,
                                         f"Verification rejected the patch: {verification['error'][:250]}",
                                         kind="verification")
            except evolution.EvolutionError:
                pass
            raise SelfModError(verification["error"])
        preview = EditEngine.diff(target_path, live_source, staged)
        if tests_source.strip():
            preview += "\n\n--- new tests: " + str(tests_path) + " ---\n" + tests_source[:2500]
        return {"kind": "heal", "preview": preview,
                "payload": {"kind": proposal_kind, "target": str(target_path), "staged": staged, "level": level,
                            "source_sha256": _sha(live_source), "edits": len(patch["edits"]),
                            "parent_node": str(patch.get("parent_node") or ""),
                            "tests_path": str(tests_path) if tests_path else "",
                            "tests_source": tests_source,
                            "exception": patch["exception"], "explanation": patch["explanation"],
                            "verification": verification, "review": review}}

    def propose(self, traceback_text: str, notes: str = "") -> dict:
        with LANE_LOCK:
            parsed = self.parse(traceback_text)
            target_path = Path(parsed["file"])
            source = target_path.read_text(encoding="utf-8")
            context = self._context(source, parsed["line"])
            patch = self._ask(f"File: {target_path.name}\nLine: {parsed['line']}\n"
                              f"Exception: {parsed['exception']}: {parsed['message']}\n"
                              f"Source context:\n```python\n{context[:MAX_PATCH]}\n```",
                              self.SYSTEM)
            patch["exception"] = f"{parsed['exception']}: {parsed['message']}"
            return self._stage(target_path, source, patch, parsed["level"], "heal")

    def _select_base_source(self, target_path: Path, disk_source: str,
                            branch_from_archive: bool) -> tuple[str, str]:
        archive = evolution.Archive()
        if branch_from_archive:
            picked = evolution.pick_parent(archive, target_path.stem)
            if picked and picked.get("id"):
                snap = archive.source_of(str(picked["id"]))
                if snap:
                    return snap, str(picked["id"])
        head = archive.head(target_path.stem)
        return disk_source, str((head or {}).get("id") or "")

    def _patcher_system_prompt(self) -> str:
        extra = evolution.PromptLab().get("patcher")
        base_default = evolution.PROMPT_DEFAULTS.get("patcher", "")
        if extra and extra != base_default:
            return self.CHANGE + "\n\n" + extra
        return self.CHANGE

    def propose_change(self, instruction: str, file_name: str = "", notes: str = "",
                       branch_from_archive: bool = False, use_crossover: bool = True) -> dict:
        """Free-form change lane: 'add a retry to X', 'return a dict here'."""
        instruction = str(instruction or "").strip()
        if not 5 <= len(instruction) <= MAX_TASK:
            raise SelfModError("An instruction of 5 to 8,000 characters is required.")
        with LANE_LOCK:
            target_path = self._resolve_target(instruction, file_name)
            level = policy_for(target_path, self.root)
            if level == "blocked":
                raise SelfModError(f"{target_path.name} is blocked from editing.")
            disk_source = target_path.read_text(encoding="utf-8")
            archive = evolution.Archive()
            base_source, parent_id = self._select_base_source(target_path, disk_source, branch_from_archive)
            lessons = evolution.Failures().prompt(target_path.stem)
            skills_ctx = evolve_engine.SkillDistiller.load_for_module(target_path.stem)
            window = _smart_source_window(base_source, instruction, MAX_PATCH)
            inspirations = (
                evolve_engine.MapElitesGrid().sample_inspirations(
                    target_path.stem, archive=archive, exclude_id=parent_id, k=2
                )
                if use_crossover else []
            )
            if inspirations or evolve_engine.EvolveBlocks.extract(base_source):
                user_prompt = evolve_engine.build_crossover_prompt(
                    target_path.name,
                    f"{instruction}\n{('Notes: ' + notes) if notes else ''}{lessons}{skills_ctx}",
                    window,
                    inspirations=inspirations,
                    max_chars=MAX_PATCH,
                )
            else:
                user_prompt = (
                    f"File: {target_path.name}\nInstruction: {instruction}\n"
                    f"{('Notes: ' + notes) if notes else ''}{lessons}{skills_ctx}\n"
                    f"Current source:\n```python\n{window}\n```"
                )
            try:
                patch = self._ask(user_prompt, self._patcher_system_prompt())
                patch["exception"] = instruction[:200]
                patch["parent_node"] = parent_id
                return self._stage(target_path, base_source, patch, level, "change", disk_source=disk_source)
            except SelfModError:
                if parent_id:
                    evolution.record_attempt(archive, parent_id)
                raise

    def propose_change_best(self, instruction: str, file_name: str = "", notes: str = "",
                            candidates: int = 2, branch_from_archive: bool = False,
                            use_crossover: bool = True) -> dict:
        """Sample several patches, rank them via CascadeEvaluator + MAP-Elites Pareto key, stage winner."""
        candidates = max(1, min(3, int(candidates or 1)))
        if candidates == 1:
            return self.propose_change(
                instruction, file_name, notes,
                branch_from_archive=branch_from_archive, use_crossover=use_crossover,
            )
        instruction = str(instruction or "").strip()
        if not 5 <= len(instruction) <= MAX_TASK:
            raise SelfModError("An instruction of 5 to 8,000 characters is required.")
        with LANE_LOCK:
            target_path = self._resolve_target(instruction, file_name)
            level = policy_for(target_path, self.root)
            disk_source = target_path.read_text(encoding="utf-8")
            archive = evolution.Archive()
            base_source, parent_id = self._select_base_source(target_path, disk_source, branch_from_archive)
            window = _smart_source_window(base_source, instruction, MAX_PATCH)
            inspirations = (
                evolve_engine.MapElitesGrid().sample_inspirations(
                    target_path.stem, archive=archive, exclude_id=parent_id, k=2
                )
                if use_crossover else []
            )
            cases = evolution.Scorecard.bench_cases(target_path.stem)
            best, best_key, ranked = None, None, []
            artifacts: list[str] = []
            hints = ("najmniejsza mozliwa zmiana, bez nowych funkcji",
                     "wersja z walidacja wejscia i czytelnym bledem",
                     "wersja laczaca najszybsze i najprostsze rozwiazania z inspiracji")
            sys_prompt = self._patcher_system_prompt()
            for index in range(candidates):
                hint = hints[index % len(hints)]
                full_instr = f"{instruction}\nWariant: {hint}\n{('Notes: ' + notes) if notes else ''}"
                prompt = evolve_engine.build_crossover_prompt(
                    target_path.name,
                    full_instr,
                    window,
                    inspirations=inspirations,
                    artifacts=artifacts,
                    max_chars=MAX_PATCH,
                )
                try:
                    draft = self._ask(prompt, sys_prompt)
                    staged = EditEngine.apply(base_source, draft["edits"])
                    ast.parse(staged, filename=str(target_path))
                except (SelfModError, SyntaxError) as error:
                    ranked.append({"candidate": index, "ok": False, "detail": str(error)[:200]})
                    continue
                cascade = evolve_engine.CascadeEvaluator.evaluate_candidate(
                    target_path.stem, staged, original_source=base_source, strict_blocks=True
                )
                if not cascade["ok"] and cascade.get("stage") in ("ast", "evolve_block", "smoke"):
                    ranked.append({"candidate": index, "ok": False, "stage": cascade.get("stage"),
                                   "detail": str(cascade.get("error") or "")[:200]})
                    continue
                passed = int((cascade.get("bench") or {}).get("ok") or 0)
                artifacts = list(cascade.get("artifacts") or [])
                ast_nodes = int((cascade.get("metrics") or {}).get("ast_nodes") or len(staged))
                peak_kb = float(cascade.get("peak_kb") or 0.0)
                ranked.append({
                    "candidate": index,
                    "ok": True,
                    "bench_ok": passed,
                    "ast_nodes": ast_nodes,
                    "peak_kb": peak_kb,
                    "size": len(staged),
                })
                key = (passed, -ast_nodes, -len(staged))
                if best is None or best_key is None or key > best_key:
                    best, best_key = draft, key
                if cases and passed == len(cases) and index >= 1:
                    break
            if best is None:
                if parent_id:
                    evolution.record_attempt(archive, parent_id)
                raise SelfModError("Every candidate failed to apply cleanly.")
            best["exception"] = instruction[:200]
            best["parent_node"] = parent_id
            proposal = self._stage(target_path, base_source, best, level, "change", disk_source=disk_source)
            proposal["payload"]["candidates"] = ranked
            proposal["preview"] = (f"Candidates: {json.dumps(ranked, ensure_ascii=False)}\n\n"
                                   + proposal["preview"])
            return proposal

    def _resolve_target(self, instruction: str, file_name: str) -> Path:
        if file_name:
            candidate = (self.root / file_name).resolve()
        else:
            names = sorted(path.name for path in self.root.glob("*.py"))
            hits = [name for name in names if name.removesuffix(".py") in instruction.casefold()]
            if len(hits) != 1:
                raise SelfModError(
                    "Name the target file explicitly; candidates: " + ", ".join(names[:24]))
            candidate = (self.root / hits[0]).resolve()
        if not candidate.is_file():
            raise SelfModError(f"{candidate.name} is not a file in the project root.")
        try:
            candidate.relative_to(self.root.resolve())
        except ValueError:
            raise SelfModError("The target must be inside the project root.") from None
        if policy_for(candidate, self.root) == "blocked":
            raise SelfModError(f"{candidate.name} is blocked from editing.")
        return candidate

    def apply_proposal(self, package: dict) -> dict:
        if not isinstance(package, dict) or not isinstance(package.get("staged"), str):
            raise SelfModError("A heal proposal is malformed.")
        with LANE_LOCK:
            target_path = Path(str(package.get("target") or "")).resolve()
            try:
                target_path.relative_to(self.root.resolve())
            except ValueError:
                raise SelfModError("The target must be inside the project root.") from None
            # Recompute the policy at apply time: the stored level was
            # attacker-controlled proposal data and could downgrade a guarded
            # file to "free".
            level = policy_for(target_path, self.root)
            if level == "blocked" or not target_path.is_file():
                raise SelfModError("That file is blocked from auto-healing.")
            current = target_path.read_text(encoding="utf-8")
            if _sha(current) != package.get("source_sha256"):
                raise SelfModError("The file changed after the proposal; refusing to apply it.")
            module = target_path.stem
            archive = evolution.Archive()
            before = evolution.Scorecard.score(module, target_path) if level != "free" else None
            tests_path = Path(package["tests_path"]).resolve() if package.get("tests_path") else None
            if tests_path is not None:
                try:
                    tests_path.relative_to((self.root / "tests").resolve())
                except ValueError:
                    raise SelfModError("Generated tests must live in the tests directory.") from None
                if tests_path.suffix != ".py":
                    raise SelfModError("Generated tests must be a Python file.")
                tests_source = str(package.get("tests_source") or "")
                if tests_source.strip():
                    try:
                        compile(tests_source, str(tests_path), "exec")
                    except SyntaxError as error:
                        raise SelfModError(f"Generated tests do not compile: {error}") from None
            tests_before = tests_path.read_text(encoding="utf-8") if tests_path and tests_path.is_file() else ""

            # Verify the staged candidate and generated tests in the shadow tree
            # BEFORE writing either one live. The old order wrote first and
            # rolled back on failure; a crash or kill in that window left
            # unverified code (and generated tests) in the real project.
            verification = Verification.run(
                target_path, package["staged"], level,
                tests_source=str(package.get("tests_source") or ""),
                tests_name=target_path.stem)
            if not verification["ok"]:
                raise SelfModError(verification["error"])

            self.backups.mkdir(parents=True, exist_ok=True)
            stamp = time.time_ns()
            backup = self.backups / f"{target_path.stem}.bak_{stamp}{target_path.suffix}"
            shutil.copy2(target_path, backup)
            tests_backup = None
            tests_created = bool(tests_path is not None and package.get("tests_source")
                                 and not tests_before)
            try:
                if tests_path is not None and package.get("tests_source"):
                    tests_path.parent.mkdir(parents=True, exist_ok=True)
                    if tests_before:
                        tests_backup = self.backups / f"{tests_path.stem}.bak_{stamp}.py"
                        shutil.copy2(tests_path, tests_backup)
                    _atomic_write(tests_path, package["tests_source"], 0o600)
                _atomic_write(target_path, package["staged"], 0o700)
                py_compile.compile(str(target_path), doraise=True)
                applied_hash = _sha(target_path.read_text(encoding="utf-8"))
                after = evolution.Scorecard.score(module, target_path) if before is not None else None
                # tol=0: any score drop signals a rollback (the hardcoded
                # 0.0-if-else carried no meaning and hid the intent).
                verdict = ("assume" if after is None
                           else evolution.gate(before, after, tol=0.0))
                if after is not None and verdict.get("rollback"):
                    try:
                        evolution.Failures().add(
                            module, f"Patch lowered the score {before['score']} -> {after['score']}; "
                                    f"{after.get('evidence', '')}",
                            evidence=str((after.get("failures") or [{}])[0].get("detail") or "")[:300],
                            kind="regressed")
                    except evolution.EvolutionError:
                        pass
                    raise SelfModError(
                        f"Score regressed ({before['score']} -> {after['score']}): {verdict['reason']}")
            except Exception as error:
                shutil.copy2(backup, target_path)
                if tests_path is not None and tests_before:
                    _atomic_write(tests_path, tests_before, 0o600)
                elif tests_path is not None and package.get("tests_source"):
                    tests_path.unlink(missing_ok=True)
                audit("heal_rollback_auto", target=str(target_path), error=str(error)[:300])
                raise SelfModError(f"Patch failed and was rolled back: {error}") from None

            patch_id = uuid.uuid4().hex[:8]
            true_parent = str(package.get("parent_node") or (archive.head(module) or {}).get("id") or "")
            node = (archive.record(module=module, file=str(target_path),
                                   parent=true_parent, score=after or {},
                                   before=before, verdict=str(verdict.get("verdict") if before else "unscored"),
                                   explanation=str(package.get("explanation") or ""),
                                   source=package["staged"])
                    if before is not None else None)
            if node is not None and after is not None:
                try:
                    grid = evolve_engine.MapElitesGrid()
                    grid.insert(
                        module=module,
                        node_id=node["id"],
                        score=float(after.get("score") or 0.0),
                        source=package["staged"],
                        duration_ms=after.get("duration_ms"),
                        explanation=str(package.get("explanation") or ""),
                    )
                    grid.migrate_islands(module)
                    if verdict.get("verdict") == "improved":
                        evolve_engine.SkillDistiller.distill_from_archive(archive)
                    evolve_engine.SelfHarness.audit_and_guard_prompt("patcher", archive)
                except Exception:
                    pass
            rows = self._history()
            rows.append({"patch_id": patch_id, "timestamp": time.time(), "file": str(target_path),
                         "backup": str(backup), "level": level, "edits": package.get("edits"),
                         "tests": str(tests_path) if tests_path else "",
                         "tests_backup": str(tests_backup) if tests_backup else "",
                         "tests_created": tests_created,
                         "exception": package.get("exception", ""),
                         "explanation": package.get("explanation", ""), "status": "applied",
                         "node": (node or {}).get("id"), "verdict": (verdict if before else {}),
                         "applied_sha256": applied_hash,
                         "verification": package.get("verification", {}),
                         "review": package.get("review", {})})
            self._save_history(rows)
            audit("heal_apply", patch=patch_id, target=str(target_path), level=level,
                  edits=package.get("edits"))
            result = {"ok": True, "patch_id": patch_id, "file": str(target_path),
                      "backup": str(backup), "level": level, "node": (node or {}).get("id"),
                      "score": after, "verdict": verdict if before else None,
                      "explanation": package.get("explanation", ""),
                      "verification": package.get("verification", {}),
                      "tests": str(tests_path) if tests_path else ""}
            if level == "guarded":
                self._schedule_restart(patch_id, target_path, backup)
                result["restart"] = {"scheduled": True}
            result["note"] = ("The file is patched and verified; "
                              + ("the service restarts in a moment." if level == "guarded"
                                 else "the module is already used on the next call."))
            return result

    def _schedule_restart(self, patch_id: str, target: Path, backup: Path) -> None:
        """Restart out of band: the HTTP handler must not kill its own process.

        The restarting process dies, so the outcome is settled by
        :meth:`reconcile` in the *next* boot, not by a thread here.
        """
        try:
            _atomic_write(PENDING_RESTART, json.dumps(
                {"patch_id": patch_id, "target": str(target), "backup": str(backup),
                 "ts": time.time()}), 0o600)
        except OSError:
            pass

        def worker() -> None:
            time.sleep(0.6)
            health = self._restart()
            audit("restart", patch=patch_id, ok=bool(health.get("ok")), error=health.get("error"))
        threading.Thread(target=worker, daemon=True).start()

    def reconcile(self, health_timeout: float = 25.0) -> dict | None:
        """Called once per boot: confirm the last guarded patch survived the restart."""
        try:
            pending = json.loads(PENDING_RESTART.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            return None
        target, backup = Path(str(pending.get("target") or "")), Path(str(pending.get("backup") or ""))
        patch_id = str(pending.get("patch_id") or "")
        # The new process is alive, so probe the patched module itself (cheap, local):
        # it must still compile and import before we call the patch healthy.
        probe = ("import importlib.util, sys; "
                 "spec = importlib.util.spec_from_file_location('selfmod_probe', sys.argv[1]); "
                 "mod = importlib.util.module_from_spec(spec); "
                 "sys.modules['selfmod_probe'] = mod; spec.loader.exec_module(mod)")
        code, detail = Verification._py(["-c", probe, str(target)], ROOT, IMPORT_TIMEOUT,
                                        readonly=[str(target.parent)]) \
            if target.is_file() else (1, "target missing")
        health = {"ok": code == 0, "detail": detail[-400:]}
        good = health["ok"]
        rows = self._history()
        for row in rows:
            if row.get("patch_id") != patch_id:
                continue
            row["restart"] = health
            row["status"] = "applied" if good else "rolled_back_health"
        self._save_history(rows)
        if not good and backup.is_file():
            try:
                shutil.copy2(backup, target)
                audit("reconcile_rollback", patch=patch_id, target=str(target))
            except OSError:
                pass
        audit("reconcile", patch=patch_id, ok=good, error=health.get("error"))
        PENDING_RESTART.unlink(missing_ok=True)
        return {"patch_id": patch_id, "ok": good}

    def _restart(self) -> dict:
        """Ask systemd to restart; the next boot's reconcile settles health.

        A restart stops this very process, so a probe here cannot be trusted to
        run. The pending marker is consumed by reconcile() in the new process,
        which imports the patched module and restores the backup on failure.
        """
        try:
            import service_control
        except ImportError:
            return {"ok": False, "error": "service_control is unavailable"}
        try:
            service_control.restart()
        except Exception as error:
            return {"ok": False, "error": str(error)[:200]}
        health = Verification.health()
        if not health.get("ok"):
            audit("health_failed", error=health.get("error"))
        return {"ok": bool(health.get("ok")), **health}

    def heal(self, traceback_text: str, dry_run: bool = False, notes: str = "") -> dict:
        proposal = self.propose(traceback_text, notes)
        if dry_run:
            return {"ok": True, "dry_run": True, **proposal["payload"], "preview": proposal["preview"]}
        return self.apply_proposal(proposal["payload"])

    def change(self, instruction: str, file_name: str = "", notes: str = "") -> dict:
        proposal = self.propose_change(instruction, file_name, notes)
        return {"ok": True, **proposal["payload"], "preview": proposal["preview"]}

    def rollback(self, patch_id: str = "latest") -> dict:
        with LANE_LOCK:
            return self._rollback_locked(patch_id)

    def _rollback_locked(self, patch_id: str = "latest") -> dict:
        rows = self._history()
        for row in reversed(rows):
            if patch_id not in (row.get("patch_id"), "latest") or row.get("status") != "applied":
                continue
            target, backup = Path(row.get("file", "")), Path(row.get("backup", ""))
            if not target.is_file() or not backup.is_file():
                raise SelfModError("The patch or its backup is missing.")
            if row.get("applied_sha256"):
                current = _sha(target.read_text(encoding="utf-8"))
                if current != row["applied_sha256"]:
                    raise SelfModError("The file changed after this patch; refusing a blind rollback.")
            shutil.copy2(backup, target)
            # Generated tests are part of the patch: restore the previous file
            # or remove the newly created one, otherwise a rollback leaves
            # model-written tests behind for the next discovery run.
            tests_path = Path(str(row.get("tests") or "")) if row.get("tests") else None
            tests_backup = Path(str(row.get("tests_backup") or "")) if row.get("tests_backup") else None
            if tests_path is not None:
                try:
                    if tests_backup is not None and tests_backup.is_file():
                        shutil.copy2(tests_backup, tests_path)
                    elif row.get("tests_created"):
                        tests_path.unlink(missing_ok=True)
                except OSError:
                    pass
            row["status"] = "rolled_back"
            row["rolled_back_at"] = time.time()
            if row.get("node"):
                try:
                    evolution.Archive().mark(str(row["node"]), "rolled_back")
                except evolution.EvolutionError:
                    pass
            self._save_history(rows)
            audit("heal_rollback", patch=row.get("patch_id"), target=str(target))
            if row.get("level") == "guarded":
                self._schedule_restart(str(row.get("patch_id")), target, backup)
            return {"ok": True, "patch_id": row.get("patch_id"), "file": str(target)}
        raise SelfModError("No applied patch matches that id.")


def parent_ok(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        return True
    except OSError:
        return False


def reconcile_pending() -> dict | None:
    """Settle a guarded patch left over from the previous process (called at boot)."""
    if not PENDING_RESTART.is_file():
        return None
    try:
        return AutoHeal(None, DEFAULT_MODEL).reconcile()
    except Exception as error:  # never block startup
        audit("reconcile_error", error=str(error)[:300])
        return None


class BenchDraft:
    """Ask the model for held-out cases; the answer is a draft, never auto-applied."""

    SYSTEM = """You write held-out behaviour tests for one Python module of a local assistant.
Return ONLY JSON: {"cases":[{"call":"function_name","kwargs":{},"expect":"exact value","level":1}]}
For an expected exception use "expect_error": true instead of "expect".
Rules: 3 to 6 cases; only public or clearly stable functions; one level 1 case (happy path),
the rest level 2 (edge case: empty input, wrong type, boundary, unicode); no network.
If a case needs a temporary file or directory, add "prepare": "short python code" that may use
tmp (a temp dir path) and set scope["kwargs"] to the final arguments. Never copy an assertion
that already exists in tests/."""

    def __init__(self, client, model: str):
        self.client = client
        self.model = str(model or DEFAULT_MODEL)

    def draft(self, module: str, limit: int = 6) -> dict:
        if self.client is None:
            raise SelfModError("Drafting a benchmark needs a model client.")
        source = (ROOT / f"{module}.py")
        if not source.is_file():
            raise SelfModError(f"{module}.py is not a module in the project root.")
        existing = ROOT / "tests" / f"test_{module}.py"
        prompt = (f"Module: {module}\nExisting tests:\n"
                       f"```python\n{(existing.read_text(encoding='utf-8')[:4000] if existing.is_file() else 'none')}\n```\n"
                       f"Source:\n```python\n{source.read_text(encoding='utf-8')[:12000]}\n```")
        messages = [{"role": "user", "content": prompt}]
        text = ""
        value = None
        for attempt in range(2):
            response = self.client.messages.create(
                model=self.model, max_tokens=1800, system=self.SYSTEM,
                messages=messages, stream=False)
            text = "\n".join(str(getattr(block, "text", "")) for block in response.content
                              if getattr(block, "type", "") == "text")
            try:
                value = _parse_json(text)
                break
            except SelfModError:
                if attempt:
                    raise
                messages = messages + [{"role": "assistant", "content": text[:2000]},
                                       {"role": "user", "content":
                                        "That was not valid JSON. Return ONLY the JSON object, nothing else."}]
        cases = []
        for case in (value.get("cases") or []):
            if not isinstance(case, dict) or not case.get("call"):
                continue
            if isinstance(case.get("expect"), str) and case["expect"].startswith("type:"):
                case["expect_type"] = case.pop("expect").split(":", 1)[1].strip()
            if case.get("expect") in ("expect_error", "error", "raises"):
                case.pop("expect", None)
                case["expect_error"] = True
            cases.append(case)
        cases = cases[:limit]
        if not cases:
            raise SelfModError("The model returned no cases.")
        passed = evolution.Scorecard.run_cases(source, cases)
        results = passed.get("results") or []
        # A dict expectation is usually too strict for a draft: retry those as subsets.
        loose = [(index, case) for index, case in enumerate(cases)
                 if isinstance(case.get("expect"), dict)
                 and index < len(results) and not results[index].get("ok")]
        if loose:
            for index, case in loose:
                case["expect_subset"] = case.pop("expect")
            again = evolution.Scorecard.run_cases(source, [case for _index, case in loose])
            for (index, _case), row in zip(loose, again.get("results") or []):
                pass
            for (index, _case), row in zip(loose, again.get("results") or []):
                results[index] = row
        for index, case in enumerate(cases):
            case["draft_ok"] = bool(results[index].get("ok")) if index < len(results) else False
        audit("bench_draft", module=module, cases=len(cases), ok=passed["ok"])
        return {"ok": True, "module": module, "cases": cases,
                "passing": passed["ok"], "total": passed["total"],
                "note": f"Save as bench/{module}.json, then run seal."}


class Planner:
    """Meta-level: pick the next changes from real failures, not from taste."""

    def __init__(self, client, model: str):
        self.client = client
        self.model = str(model or DEFAULT_MODEL)

    def suggest(self, limit: int = 3, system: str | None = None) -> dict:
        """Ask the model for next changes grounded only in real signals.

        Failing held-out benchmarks, recorded lessons and the audit trail feed
        the prompt; a client-free run still returns the deterministic signal
        summary so ``suggest`` never depends on the model being available.
        """
        limit = max(1, min(int(limit or 3), 5))
        archive = evolution.Archive()
        prompt = evolution.suggest_prompt(ROOT, archive, audit_tail(40), limit=limit)
        if self.client is None:
            return {"ok": True, "skipped": True, "prompt": prompt[:2000],
                    "suggestions": [], "reason": "no model client; signals only"}
        response = self._text(prompt, system or evolution.SUGGEST_SYSTEM, max_tokens=2500)
        value = _parse_json(response)
        rows = value.get("suggestions")
        if not isinstance(rows, list):
            raise SelfModError("The planner response has no suggestions.")
        suggestions = []
        for row in rows[:limit]:
            if not isinstance(row, dict):
                continue
            raw_file = Path(str(row.get("file") or "").strip()).name
            raw_stem = raw_file[:-3] if raw_file.lower().endswith(".py") else raw_file
            clean_stem = re.sub(r"[^a-z0-9_]+", "_", raw_stem.lower()).strip("_")
            if not clean_stem or not clean_stem[0].isalpha():
                continue
            suggestions.append({"file": f"{clean_stem[:64]}.py",
                                "instruction": str(row.get("instruction") or "")[:800],
                                "evidence": str(row.get("evidence") or "")[:400]})
        audit("planner", count=len(suggestions))
        return {"ok": True, "skipped": False, "suggestions": suggestions,
                "prompt": prompt[:2000]}

    def _text(self, prompt: str, system: str, max_tokens: int = 2500) -> str:
        response = self.client.messages.create(
            model=self.model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": prompt}], stream=False)
        return "\n".join(str(getattr(block, "text", "")) for block in response.content
                         if getattr(block, "type", "") == "text")

class SelfModification:
    """Facade used by the HTTP lane and the Operator tools."""

    def __init__(self, client, model: str, allow_install: bool = False):
        self.client = client
        self.model = str(model or DEFAULT_MODEL)
        self.registry = DynamicRegistry()
        self.rules = LearnedRules()
        self.forge = SkillForge(client, self.model, self.registry, allow_install=allow_install)
        self.heal = AutoHeal(client, self.model)
        self.gate = ProposalGate()
        self.planner = Planner(client, self.model)
        self.bench = BenchDraft(client, self.model)
        self.prompt_lab = evolution.PromptLab()

    def close(self) -> None:
        """Release the provider client owned by this facade."""
        client, self.client = self.client, None
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

    def status(self) -> dict:
        return {"ok": True, "skills": self.registry.list(), "rules": self.rules.list(True),
                "patches": self.heal.history()[:10], "tools": len(self.registry.skills),
                "limits": {"max_edits": MAX_EDITS, "max_patch": MAX_PATCH, "timeout": TEST_TIMEOUT,
                           "proposal_ttl": self.gate.ttl},
                "policy": {"guarded": len(GUARDED_FILES), "blocked_files": sorted(BLOCKED_FILES),
                           "blocked_dirs": sorted(BLOCKED_DIRS)},
                "audit": audit_tail(15),
                "bench_drift": evolution.Bench.drift(),
                "curriculum": evolution.Curriculum.summary(),
                "failures": evolution.Failures().rows()[-8:],
                "quarantined": [name for name, row in self.registry.stats().items()
                                if row.get("quarantined")],
                "sandbox": evolution.sandbox_available(),
                "proposals": [self.gate.public(row.get("id", "")) for row in self.gate._rows()
                                   if row.get("expires_at", 0) > time.time() and row.get("id")]}

    def forge_skill(self, goal: str, name: str = "") -> dict:
        return self.forge.forge(goal, name)

    def propose_skill(self, goal: str, name: str = "") -> dict:
        proposal = self.forge.propose(goal, name)
        return {**self.gate.create("skill", proposal["payload"], proposal["preview"]),
                "preview": proposal["preview"]}

    def propose_heal(self, traceback_text: str, notes: str = "") -> dict:
        proposal = self.heal.propose(traceback_text, notes)
        return {**self.gate.create("heal", proposal["payload"], proposal["preview"]),
                "preview": proposal["preview"]}

    def propose_change(self, instruction: str, file_name: str = "", notes: str = "",
                       candidates: int = 1, branch_from_archive: bool = False) -> dict:
        proposal = self.heal.propose_change_best(
            instruction, file_name, notes, candidates, branch_from_archive=branch_from_archive
        )
        return {**self.gate.create("change", proposal["payload"], proposal["preview"]),
                "preview": proposal["preview"]}

    def apply_proposal(self, proposal_id: str, token: str) -> dict:
        with LANE_LOCK:
            public = self.gate.public(proposal_id)
            kind = (public or {}).get("kind")
        payload = self.gate.consume(proposal_id, token)
        if kind == "skill":
            return self.forge.apply_package(payload)
        if kind in ("heal", "change"):
            return self.heal.apply_proposal(payload)
        raise SelfModError("That proposal kind is not supported.")

    def watch_once(self, auto_apply: bool = False) -> dict:
        """Scan the journal, propose one patch per new traceback, with a per-module cooldown."""
        watch = evolution.RuntimeWatch()
        found = watch.scan()
        handled = []
        for item in found:
            if item.get("error"):
                return {"ok": False, "error": item["error"]}
            module = item.get("module") or ""
            recent = watch.state().get("handled") or {}
            open_modules = {Path(str((row.get("payload") or {}).get("target") or "")).stem
                            for row in self.gate._rows()}
            if module and time.time() - float(recent.get(module) or 0) < WATCH_COOLDOWN:
                watch.record({"id": item["id"], "module": module, "status": "cooldown"})
                handled.append({"id": item["id"], "module": module, "status": "cooldown"})
                continue
            if module and module in open_modules:
                watch.record({"id": item["id"], "module": module, "status": "already_open"})
                handled.append({"id": item["id"], "module": module, "status": "already_open"})
                continue
            try:
                created = self.propose_heal(item["traceback"])
            except SelfModError as error:
                watch.record({"id": item["id"], "module": module, "status": "rejected",
                              "detail": str(error)[:300]})
                handled.append({"id": item["id"], "module": module, "status": "rejected",
                                "detail": str(error)[:300]})
                continue
            except Exception as error:
                # An unreadable traceback file or disk hiccup must not stop the
                # scan: the remaining items still get their proposals.
                detail = f"{type(error).__name__}: {str(error)[:180]}"
                watch.record({"id": item["id"], "module": module,
                              "status": "error", "detail": detail[:300]})
                handled.append({"id": item["id"], "module": module, "status": "error",
                                "detail": detail[:200]})
                continue
            watch.save_state(handled={**recent, module: time.time()})
            status, detail = "proposed", ""
            if auto_apply and module and evolution.Scorecard.bench_cases(module):
                try:
                    self.apply_proposal(created["proposal_id"], created["token"])
                    status = "applied"
                except SelfModError as error:
                    status = "apply_failed"
                    detail = str(error)[:300]
            watch.record({"id": item["id"], "module": module, "status": status,
                          "proposal": created["proposal_id"], "detail": detail})
            handled.append({"id": item["id"], "module": module, "status": status,
                            "proposal": created["proposal_id"], "token": created["token"],
                            "detail": detail})
        audit("watch_scan", found=len(found), handled=len(handled))
        return {"ok": True, "found": len(found), "handled": handled}

    def watch_state(self) -> dict:
        return evolution.RuntimeWatch().state()

    def watch_enable(self, enabled: bool = True, auto_apply: bool = False) -> dict:
        return evolution.RuntimeWatch().save_state(enabled=enabled, auto_apply=auto_apply,
                                                   since=time.time())

    def draft_bench(self, module: str) -> dict:
        return self.bench.draft(module)

    def suggest(self, limit: int = 3) -> dict:
        custom_planner = evolution.PromptLab().get("planner") or evolution.SUGGEST_SYSTEM
        return self.planner.suggest(limit, system=custom_planner)

    def evolution(self) -> dict:
        archive = evolution.Archive()
        skills = sorted(p.name for p in evolve_engine.SkillDistiller.skills_dir().glob("*.md"))[-15:]
        return {"ok": True, "summary": archive.summary(), "best": archive.ranked(5),
                "map_elites": evolve_engine.MapElitesGrid().summary(),
                "distilled_skills": skills,
                "curriculum": evolution.Curriculum.summary(),
                "failures": evolution.Failures().rows()[-20:]}

    def mutation_test(self, module: str, max_mutants: int = 6) -> dict:
        return evolve_engine.MutationTester.evaluate_suite(module, max_mutants=max_mutants)

    def adversarial_break(self, module: str) -> dict:
        return evolve_engine.AdversarialBreaker.generate_draft_cases(
            module, client=self.client, model=self.model
        )

    def promote_bench_draft(self, module: str, only_passing: bool = True) -> dict:
        return evolve_engine.AdversarialBreaker.promote_draft(module, only_passing=only_passing)

    def evolve_harness(self, key: str = "patcher") -> dict:
        res = evolve_engine.SelfHarness.evolve_prompt_from_failures(key=key, lab=self.prompt_lab)
        distilled = evolve_engine.SkillDistiller.distill_from_archive()
        return {**res, "distilled": distilled}

    def branch_point(self, module: str = "") -> dict:
        archive = evolution.Archive()
        node = evolution.pick_parent(archive, module or None)
        if node is None:
            return {"ok": True, "node": None, "note": "archive is empty; start from the current file"}
        return {"ok": True, "node": {key: node.get(key) for key in
                                     ("id", "module", "score", "verdict")},
                "cmp": archive.descendants(node["id"])}

    def seal_bench(self) -> dict:
        return {"ok": True, "files": evolution.Bench.seal()}

    def bench_drift(self) -> dict:
        return {"ok": True, **evolution.Bench.drift()}

    def run_skill(self, name: str, arguments: dict) -> Any:
        return self.registry.run(name, arguments)

    def reset_skill_stats(self, name: str = "") -> dict:
        return {"ok": True, "stats": self.registry.reset_stats(name)}

    def heal_traceback(self, traceback_text: str, dry_run: bool = False, notes: str = "") -> dict:
        return self.heal.heal(traceback_text, dry_run=dry_run, notes=notes)

    def change_file(self, instruction: str, file_name: str = "", notes: str = "") -> dict:
        return self.heal.change(instruction, file_name, notes)

    def rollback(self, patch_id: str = "latest") -> dict:
        return self.heal.rollback(patch_id)
