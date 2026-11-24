"""Evolution layer for the self-modification lane: scorecard, archive, gating.

The literature on self-improving agents (DGM arXiv 2505.22954, SICA 2504.15228,
HGM 2510.21614, Gödel Agent 2410.04444, Voyager 2305.16291) never gates a change
on "the tests the agent itself may edit". It gates on an *external* measurement,
keeps every version in an archive, and picks what to improve next from that
archive. This module supplies exactly those three pieces for Jarvis, in a size
that runs locally in seconds:

  * Scorecard - held-out behaviour cases (``bench/<module>.json``) plus the
    module's own unit tests. Held-out cases live outside ``tests/``, so a patch
    that "fixes" a test cannot fake a better score.
  * Archive   - every applied patch is a node with parent, score, hash and
    descendant count, so a lineage can be walked and compared (CMP in HGM terms).
  * Gate      - a change that lowers the score is rolled back automatically;
    an equal score is kept but flagged, never silently called an improvement.

Benchmark poisoning (arXiv 2609.17817) is why the held-out file is read-only
for the lane: it is scored *before* and *after* without being regenerated.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
BENCH = ROOT / "bench"
STATE = Path.home() / ".jarvis-tools" / "selfmod"
ARCHIVE = STATE / "archive.json"
FAILURES = STATE / "failures.json"
PROMPTS = STATE / "prompts.json"
BENCH_MANIFEST = BENCH / "manifest.json"
MAX_CASES = 200
CASE_TIMEOUT = 20.0
SLOW_PENALTY = 3.0


class EvolutionError(Exception):
    """A scoring or archive problem."""


def _read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return fallback


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Unique temp name: two threads of this process must never share one file
    # (a fixed pid-suffixed name let a concurrent replace clobber the payload).
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}-{time.time_ns()}")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def _limit_child(timeout: float) -> None:
    """Local mirror of self_modify's rlimits (evolution must not import it)."""
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


def _bench_environment() -> dict:
    """Minimal, fixed environment for benchmark children (no host variables)."""
    return {"PATH": os.environ.get("PATH", ""), "HOME": "/tmp", "TMPDIR": "/tmp",
            "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1",
            # The bench sandbox has no network; keep fastembed from trying to
            # download a model into its disposable HOME and stalling the suite.
            "JARVIS_EMBEDDINGS": "off"}


def _kill_group(process) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class Scorecard:
    """Deterministic score in [0, 1] for one module, plus the evidence behind it."""

    @staticmethod
    def bench_cases(module: str) -> list[dict]:
        path = BENCH / f"{module}.json"
        value = _read_json(path, [])
        rows = value.get("cases") if isinstance(value, dict) else value
        if not isinstance(rows, list):
            return []
        return [row for row in rows if isinstance(row, dict)][:MAX_CASES]

    @staticmethod
    def run_cases(path: Path, cases: list[dict]) -> dict:
        """Call functions of *path* in a child process and compare results."""
        if not cases:
            return {"ok": 0, "total": 0, "results": []}
        refusal = sandbox_refusal()
        if refusal:
            return {"ok": 0, "total": len(cases), "results": [], "error": refusal}
        harness_body = r"""
import importlib.util, json, os, sys, tempfile

# The untrusted module is imported only after the per-run nonce has been read
# from stdin, and the verdict is written with saved references. A module that
# prints its own "results" line (or exits early) cannot fake the verdict.
write, dumps = os.write, json.dumps
nonce = sys.stdin.readline().strip()
if not nonce:
    raise SystemExit(2)
marker = "__JARVIS_BENCH_" + nonce + "__"

def emit(payload):
    write(1, (marker + dumps(payload) + "\n").encode("utf-8", "replace"))

path, cases = sys.argv[1], json.loads(sys.argv[2])
spec = importlib.util.spec_from_file_location("bench_target", path)
module = importlib.util.module_from_spec(spec)
sys.modules["bench_target"] = module
rows = []
try:
    spec.loader.exec_module(module)
except BaseException as exc:
    emit({"load_error": str(exc)[:400], "results": []})
    raise SystemExit(0)
workdir = tempfile.mkdtemp(prefix="jarvis-bench-")
for index, case in enumerate(cases):
    name, kwargs = case.get("call"), case.get("kwargs") or {}
    args = []
    if case.get("prepare"):
        scope = {"tmp": workdir, "module": module}
        scope["scope"] = scope
        try:
            exec(case["prepare"], scope)
        except Exception as exc:
            rows.append({"index": index, "ok": False, "detail": "prepare: " + str(exc)[:160]})
            continue
        if "kwargs" in scope:
            kwargs = scope["kwargs"]
        args = scope.get("args") or []
    if case.get("method"):
        owner = scope.get("instance") if case.get("prepare") else None
        function = getattr(owner, case["method"], None) if owner is not None else None
        name = case["method"]
    else:
        function = getattr(module, name, None)
    if not callable(function):
        rows.append({"index": index, "ok": False, "detail": "missing callable " + str(name)})
        continue
    try:
        got = function(*args, **kwargs)
    except Exception as exc:
        rows.append({"index": index, "ok": "expect_error" in case, "detail": str(exc)[:200]})
        continue
    if "expect_error" in case:
        rows.append({"index": index, "ok": False, "detail": "expected an exception"})
    elif "expect_type" in case:
        wanted_type = {"dict": dict, "list": list, "str": str, "int": int, "float": (int, float),
                       "bool": bool, "none": type(None), "object": object}.get(str(case["expect_type"]).lower())
        ok = wanted_type is not None and isinstance(got, wanted_type)
        rows.append({"index": index, "ok": ok, "detail": "" if ok else f"got {type(got).__name__}"})
    elif "expect_subset" in case:
        wanted = case["expect_subset"] or {}
        checked = got[0] if isinstance(got, tuple) and got else got
        ok = isinstance(checked, dict) and all(
            checked.get(key) == value for key, value in wanted.items() if value is not None)
        rows.append({"index": index, "ok": ok, "detail": "" if ok else f"got {str(got)[:140]!r}"})
    elif "expect" in case and got != case["expect"]:
        rows.append({"index": index, "ok": False, "detail": f"got {str(got)[:120]!r}"})
    elif "expect_contains" in case and str(case["expect_contains"]) not in str(got):
        rows.append({"index": index, "ok": False, "detail": f"got {str(got)[:120]!r}"})
    else:
        rows.append({"index": index, "ok": True, "detail": ""})
emit({"results": rows})
"""
        # A benchmark target runs in this same interpreter and can read
        # `sys.modules['__main__']`. Keep the nonce/marker in a function local
        # so a module cannot print a forged verdict from the globals.
        harness = ("def __jarvis_bench__():\n"
                   + "\n".join("    " + line for line in harness_body.splitlines())
                   + "\n__jarvis_bench__()\n")
        process = None
        nonce = uuid.uuid4().hex
        marker = "__JARVIS_BENCH_" + nonce + "__"
        try:
            process = subprocess.Popen(
                # The harness must obey the same sandbox + rlimit rules as the
                # SkillCrucible worker: model-supplied "prepare" code previously
                # ran here without any sandbox at all.
                sandbox_argv([sys.executable, "-c", harness, str(path), json.dumps(cases)],
                             readonly=[str(path.parent)]),
                cwd=str(ROOT), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True, env=_bench_environment(),
                preexec_fn=lambda: _limit_child(CASE_TIMEOUT))
        except OSError as error:
            return {"ok": 0, "total": len(cases), "results": [], "error": str(error)[:200]}
        try:
            stdout, stderr = process.communicate(input=nonce + "\n", timeout=CASE_TIMEOUT)
        except subprocess.TimeoutExpired:
            _kill_group(process)
            try:
                process.communicate(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                pass
            return {"ok": 0, "total": len(cases), "results": [], "error": "benchmark timed out"}
        payload = None
        for line in reversed((stdout or "").splitlines()):
            if not line.startswith(marker):
                continue
            try:
                candidate = json.loads(line[len(marker):])
            except ValueError:
                continue
            if isinstance(candidate, dict):
                payload = candidate
                break
        if payload is None:
            # A module that exits before the harness can print, or forges a
            # plain results line, must not look like a passing benchmark.
            detail = (stderr or "").strip()[-300:]
            return {"ok": 0, "total": len(cases), "results": [],
                    "error": "benchmark verdict missing (forged or truncated output)"
                             + (f": {detail}" if detail else "")}
        results = [row for row in (payload.get("results") or []) if isinstance(row, dict)]
        if payload.get("load_error"):
            return {"ok": 0, "total": len(cases), "results": results, "error": payload["load_error"]}
        passed = sum(1 for row in results if row.get("ok"))
        # A forged/duplicated row list must not score above the real case count.
        return {"ok": min(passed, len(cases)), "total": len(cases), "results": results}

    @classmethod
    def unittests(cls, module: str) -> dict:
        test_file = ROOT / "tests" / f"test_{module}.py"
        if not test_file.is_file():
            return {"ok": 0, "total": 0, "results": [], "skipped": True}
        home = Path(tempfile.mkdtemp(prefix="jarvis-bench-home-"))
        try:
            environment = _bench_environment()
            environment.update({"HOME": str(home), "TMPDIR": str(home)})
            # The patched module is untrusted: run its test file in the same
            # read-only-tree sandbox as the benchmark, not in the live process.
            try:
                done = subprocess.Popen(
                    sandbox_argv([sys.executable, "-m", "unittest", f"tests.test_{module}", "-q"],
                                 writable=home, cwd=ROOT),
                    cwd=str(ROOT), env=environment, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            except OSError as error:
                return {"ok": 0, "total": 1, "results": [], "error": str(error)[:300]}
            try:
                stdout, stderr = done.communicate(timeout=180)
            except subprocess.TimeoutExpired:
                _kill_group(done)
                try:
                    done.communicate(timeout=5)
                except (subprocess.TimeoutExpired, OSError):
                    pass
                return {"ok": 0, "total": 1, "results": [], "error": "tests timed out"}
        finally:
            shutil.rmtree(home, ignore_errors=True)
        tail = (stderr or "") + "\n" + (stdout or "")
        ran_match = re.search(r"Ran\s+(\d+)\s+tests?\b", tail)
        ran = int(ran_match.group(1)) if ran_match else 0
        if done.returncode == 0:
            total = max(ran, 1)
            return {"ok": total, "total": total, "results": []}
        if ran > 0:
            fail_m = re.search(r"failures=(\d+)", tail)
            err_m = re.search(r"errors=(\d+)", tail)
            bad_count = (int(fail_m.group(1)) if fail_m else 0) + (int(err_m.group(1)) if err_m else 0)
            if bad_count == 0:
                bad_count = 1
            passed = max(0, ran - min(ran, bad_count))
            return {"ok": passed, "total": ran, "results": [], "error": tail[-400:]}
        return {"ok": 0, "total": 1, "results": [], "error": tail[-400:]}

    @classmethod
    def score(cls, module: str, path: Path) -> dict:
        """Weighted score: held-out behaviour cases dominate, tests corroborate."""
        started = time.time()
        cases = cls.bench_cases(module)
        bench = cls.run_cases(path, cases)
        tests = cls.unittests(module)
        duration = int((time.time() - started) * 1000)
        parts: list[tuple[str, float, float]] = []
        if bench["total"]:
            parts.append(("bench", bench["ok"] / bench["total"], 0.7))
        if tests["total"]:
            parts.append(("tests", tests["ok"] / tests["total"], 0.3))
        if not parts:
            return {"module": module, "score": 1.0, "coverage": 0.0, "bench": bench,
                    "tests": tests, "duration_ms": duration, "signal": "none",
                    "evidence": "no benchmark or tests for this module"}
        weight = sum(item[2] for item in parts)
        value = sum(item[1] * item[2] for item in parts) / weight
        failures = [{"check": "bench", "detail": row.get("detail")}
                    for row in bench["results"] if not row.get("ok")]
        return {"module": module, "score": round(value, 4), "coverage": round(weight, 2),
                "duration_ms": duration, "signal": "bench+tests" if bench["total"] else "tests",
                "bench": {"ok": bench["ok"], "total": bench["total"]},
                "tests": {"ok": tests["ok"], "total": tests["total"]},
                "failures": failures[:8],
                "evidence": "held-out cases + unit tests" if bench["total"] else "unit tests only"}


class Archive:
    """Lineage of applied patches with their scores and stored source snapshots (DGM/HGM)."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path or ARCHIVE)
        self.snapshots_dir = self.path.parent / "snapshots"

    def rows(self) -> list[dict]:
        value = _read_json(self.path, [])
        return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []

    def save(self, rows: list[dict]) -> None:
        _write_json(self.path, rows[-500:])

    def head(self, module: str) -> dict | None:
        for row in reversed(self.rows()):
            if row.get("module") == module and row.get("status") == "applied":
                return row
        return None

    def record(self, *, module: str, file: str, parent: str, score: dict,
               before: dict | None, verdict: str, explanation: str = "",
               source: str = "") -> dict:
        rows = self.rows()
        node_id = uuid.uuid4().hex[:10]
        source_sha = ""
        has_snapshot = False
        if isinstance(source, str) and source:
            source_sha = _sha(source)
            try:
                self.snapshots_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                snap = self.snapshots_dir / f"{node_id}.py"
                tmp = snap.with_name(f".{node_id}.tmp-{os.getpid()}-{time.time_ns()}")
                tmp.write_text(source, encoding="utf-8")
                tmp.replace(snap)
                has_snapshot = True
            except OSError:
                has_snapshot = False
        row = {"id": node_id, "ts": time.time(), "module": module, "file": file,
               "parent": parent, "score": score.get("score"), "coverage": score.get("coverage"),
               "before": (before or {}).get("score"), "verdict": verdict,
               "explanation": explanation[:300], "status": "applied",
               "sha": _sha(json.dumps(score, sort_keys=True)),
               "source_sha": source_sha, "has_snapshot": has_snapshot}
        rows.append(row)
        self.save(rows)
        return row

    def source_of(self, node_id: str) -> str | None:
        """Return verified source snapshot for an archive node, or None if unavailable."""
        clean_id = re.sub(r"[^a-f0-9]", "", str(node_id or "").lower())
        if not clean_id:
            return None
        snap = self.snapshots_dir / f"{clean_id}.py"
        if not snap.is_file():
            return None
        try:
            text = snap.read_text(encoding="utf-8")
        except OSError:
            return None
        for row in reversed(self.rows()):
            if row.get("id") == clean_id:
                expected = row.get("source_sha") or ""
                if expected and _sha(text) != expected:
                    return None
                return text
        return text

    def mark(self, patch_id: str, status: str) -> None:
        rows = self.rows()
        for row in rows:
            if row.get("id") == patch_id:
                row["status"] = status
                row["marked_at"] = time.time()
        self.save(rows)

    @staticmethod
    def _by_parent(rows: list[dict]) -> dict[str, list[dict]]:
        """One parent→children pass: the BFS must not rescan every row per
        generation, and ranked() used to pay that per applied row."""
        index: dict[str, list[dict]] = {}
        for row in rows:
            index.setdefault(row.get("parent"), []).append(row)
        return index

    def descendants(self, node_id: str, only_improved: bool = False,
                    index: dict[str, list[dict]] | None = None,
                    rows: list[dict] | None = None) -> int:
        children_of = index if index is not None else self._by_parent(rows if rows is not None
                                                                      else self.rows())
        count, frontier, seen = 0, [node_id], {node_id}
        while frontier:
            children, nxt = [], set()
            for node in frontier:
                for row in children_of.get(node, ()):
                    row_id = row.get("id") or ""
                    if row_id in seen:
                        continue  # a lineage cycle must not double-count or hang
                    seen.add(row_id)
                    children.append(row)
                    nxt.add(row_id)
            if not children:
                return count
            count += sum(1 for row in children
                         if row.get("verdict") == "improved" or not only_improved)
            frontier = sorted(nxt)
        return count

    def ranked(self, limit: int = 10) -> list[dict]:
        raw = self.rows()
        index = self._by_parent(raw)
        rows = [row for row in raw if row.get("status") == "applied"]
        scored = [{**row, "cmp": self.descendants(row["id"], index=index)} for row in rows]
        scored.sort(key=lambda row: (row.get("cmp", 0), row.get("score") or 0), reverse=True)
        return scored[:limit]

    def summary(self) -> dict:
        rows = self.rows()
        verdicts: dict[str, int] = {}
        for row in rows:
            verdicts[row.get("verdict", "unknown")] = verdicts.get(row.get("verdict", "unknown"), 0) + 1
        return {"nodes": len(rows), "applied": sum(1 for row in rows if row.get("status") == "applied"),
                "verdicts": verdicts, "best": self.ranked(3)}


def gate(before, after, *, tol=0.0):
    """Decide what to do with a scored change: keep, flag, slow down or roll back."""
    if not before:
        return {"verdict": "baseline", "delta": None, "rollback": False,
                "reason": "no previous score to compare against"}
    if after.get("signal") == "none" and before.get("signal") == "none":
        return {"verdict": "unscored", "delta": None, "rollback": False,
                "reason": "no benchmark or tests; only compile and import were checked"}
    delta = round(after.get("score", 0.0) - before.get("score", 0.0), 4)
    if delta < -tol:
        return {"verdict": "regressed", "delta": delta, "rollback": True,
                "reason": f"score fell by {abs(delta):.3f}"}
    old_ms, new_ms = before.get("duration_ms"), after.get("duration_ms")
    slow = bool(old_ms and new_ms and new_ms > old_ms * SLOW_PENALTY)
    ratio = round(new_ms / old_ms, 2) if slow else None
    if delta == 0 and slow:
        return {"verdict": "neutral", "delta": delta, "rollback": False,
                "ratio": ratio, "reason": f"score unchanged and {ratio}x slower"}
    if delta == 0:
        return {"verdict": "neutral", "delta": delta, "rollback": False,
                "reason": "score unchanged; kept but not called an improvement"}
    return {"verdict": "improved", "delta": delta, "rollback": False,
            "reason": f"score rose by {delta:.3f}"}


SUGGEST_SYSTEM = """You are Jarvis' improvement planner. Given the audit trail, failing
benchmarks and the patch archive, name the THREE highest-value next changes.
Return ONLY JSON: {"suggestions":[{"file":"name.py","instruction":"what to change and why",
"evidence":"which failure or node this follows from"}]}
Rules: one file per suggestion; smallest instruction that fixes an observed weakness;
prefer modules with failing held-out cases over cosmetic polish; never invent a failure;
never repeat a change that is already applied unless you name what is still wrong with it.
"""


def suggest_prompt(root: Path, archive: Archive, audit_tail: list[dict], limit: int = 3) -> str:
    """Build the planner prompt from real signals only: curriculum first."""
    failing: list[str] = []
    for row in Curriculum.summary():
        if row["failed"]:
            nxt = Curriculum.next(row["module"])
            failing.append(f"{row['module']}.py -> {row['failed']}/{row['cases']} failing, "
                           f"easiest open (level {row.get('next_level') or row['max_level']}): "
                           f"{json.dumps(nxt, ensure_ascii=False, default=str)[:220]}")
    lessons = []
    for row in Failures().rows()[-14:]:
        if (root / f"{row.get('module')}.py").is_file():
            lessons.append(f"{row.get('module')}: {row.get('lesson')}")
    audit = [f"{row.get('event')} {row.get('target') or row.get('patch') or ''}".strip()
             for row in audit_tail[-40:]]
    best = [f"{row['module']} score={row.get('score')} cmp={row.get('cmp')}" for row in archive.ranked(5)]
    done = [f"{row.get('module')}: {str(row.get('explanation') or '')[:90]}"
            for row in archive.rows()[-10:] if row.get("status") == "applied"]
    return ("Failing held-out cases:\n" + ("\n".join(failing) or "none") +
            "\n\nRecent audit trail:\n" + ("\n".join(audit) or "empty") +
            "\n\nLessons from failed attempts:\n" + ("\n".join(lessons) or "none") +
            "\n\nAlready applied (do not propose the same again):\n" + ("\n".join(done) or "none") +
            "\n\nBest archive nodes:\n" + ("\n".join(best) or "empty") +
            f"\n\nName at most {limit} changes.")


# --------------------------------------------------------------------------- #
# Exploration: branch from the archive instead of always from head
# --------------------------------------------------------------------------- #
def _softmax_pick(rows, key, temperature=0.7):
    """Weighted random pick; a higher temperature flattens the distribution."""
    if not rows:
        return None
    weights = []
    for row in rows:
        value = max(0.01, float(key(row) or 0.0))
        weights.append(value ** (1.0 / max(0.05, temperature)))
    total = sum(weights)
    needle = random.random() * total
    upto = 0.0
    for row, weight in zip(rows, weights):
        upto += weight
        if upto >= needle:
            return row
    return rows[-1]


def record_attempt(archive: Archive, node_id: str) -> None:
    """Increment exploration attempt counter on a parent node for UCB/DGM decay."""
    if not node_id:
        return
    rows = archive.rows()
    changed = False
    for row in rows:
        if row.get("id") == node_id:
            row["attempts"] = int(row.get("attempts") or 0) + 1
            changed = True
    if changed:
        archive.save(rows)


Archive.record_attempt = record_attempt  # type: ignore[attr-defined]


def pick_parent(archive, module=None, temperature=0.7):
    """Choose which node to grow from: productive lineage + score, decayed by failed attempts (DGM/UCB).

    This is what turns a queue into a tree (DGM). A node that produced good
    descendants keeps getting chances; an over-hammered branch with unimproved
    children decays by 1/sqrt(1 + wasted) so fresh leaves get explored.
    """
    all_rows = archive.rows()
    rows = [row for row in all_rows if row.get("status") == "applied"
            and (module is None or row.get("module") == module)]
    if not rows:
        return None
    index = archive._by_parent(all_rows)
    scored = []
    for row in rows:
        nid = row["id"]
        imp = archive.descendants(nid, only_improved=True, index=index)
        direct_bad = sum(1 for c in index.get(nid, ()) if c.get("verdict") != "improved")
        wasted = direct_bad + int(row.get("attempts") or 0)
        scored.append({**row, "cmp": imp, "wasted": wasted})
    return _softmax_pick(
        scored,
        lambda row: ((row["cmp"] + 1) * ((row.get("score") or 0.5) + 0.1)) / ((1.0 + row["wasted"]) ** 0.5),
        temperature,
    )


# --------------------------------------------------------------------------- #
# Failure memory: a lost patch must leave a lesson
# --------------------------------------------------------------------------- #
class Failures:
    """Reflections from regressed or rejected patches, fed into the next attempt."""

    def __init__(self, path=None):
        self.path = Path(path or FAILURES)

    def rows(self):
        value = _read_json(self.path, [])
        return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []

    def add(self, module="", lesson="", evidence="", kind="rejected"):
        clean = str(lesson or "").strip()
        if not clean:
            raise EvolutionError("A failure lesson cannot be empty.")
        rows = self.rows()
        for row in rows:
            if row.get("lesson", "").casefold() == clean.casefold() and row.get("module") == module:
                row["count"] = int(row.get("count") or 1) + 1
                row["ts"] = time.time()
                _write_json(self.path, rows[-100:])
                return row
        row = {"id": uuid.uuid4().hex[:8], "ts": time.time(), "module": str(module or ""),
               "kind": str(kind or "rejected")[:20], "lesson": clean[:800],
               "evidence": str(evidence or "")[:400], "count": 1}
        rows.append(row)
        _write_json(self.path, rows[-100:])
        return row

    def for_module(self, module, limit=5):
        rows = [row for row in self.rows() if row.get("module") == module]
        rows.sort(key=lambda row: (int(row.get("count") or 1), row.get("ts") or 0), reverse=True)
        return rows[:limit]

    def prompt(self, module, limit=5):
        rows = self.for_module(module, limit)
        if not rows:
            return ""
        return ("\n\nLESSONS FROM PREVIOUS FAILED ATTEMPTS ON THIS FILE "
                "(do not repeat them):\n"
                + "\n".join(f"- {row['lesson']} (x{row.get('count') or 1})" for row in rows))


# --------------------------------------------------------------------------- #
# Curriculum: raise difficulty instead of polishing what already passes
# --------------------------------------------------------------------------- #
class Curriculum:
    """Reads ``level`` from bench cases and names the next unsolved rung."""

    @staticmethod
    def unsolved(module, path=None):
        path = Path(path or (ROOT / f"{module}.py"))
        cases = Scorecard.bench_cases(module)
        run = Scorecard.run_cases(path, cases)
        failed = {row.get("index") for row in run.get("results", []) if not row.get("ok")}
        return [dict(case, index=index, level=int(case.get("level") or 1))
                for index, case in enumerate(cases) if index in failed]

    @classmethod
    def next(cls, module, path=None):
        pending = cls.unsolved(module, path)
        if not pending:
            return None
        pending.sort(key=lambda case: case["level"])
        return pending[0]

    @classmethod
    def summary(cls):
        """Per-module bench results, cached briefly.

        Each entry spawns a scorecard child process; the studio polls
        /self/status every few seconds while a job runs, so without a short
        TTL one open tab multiplied Node/Python launches for nothing.
        """
        stamped = time.time()
        cached = cls._summary_cache
        if cached is not None and stamped - cached[0] < 15:
            return cached[1]
        out = []
        for bench_file in sorted(BENCH.glob("*.json")):
            module = bench_file.stem
            if not (ROOT / f"{module}.py").is_file():
                continue
            cases = Scorecard.bench_cases(module)
            run = Scorecard.run_cases(ROOT / f"{module}.py", cases)
            bad = {row.get("index") for row in run.get("results", []) if not row.get("ok")}
            failed = [case for index, case in enumerate(cases) if index in bad]
            out.append({"module": module, "cases": len(cases), "failed": len(failed),
                        "max_level": max([int(case.get("level") or 1) for case in cases] or [0]),
                        "next_level": min([int(case.get("level") or 1) for case in failed] or [0])})
        cls._summary_cache = (stamped, out)
        return out

    @classmethod
    def invalidate(cls):
        cls._summary_cache = None


Curriculum._summary_cache = None


# --------------------------------------------------------------------------- #
# Benchmark integrity: the lane must not silently rewrite what grades it
# --------------------------------------------------------------------------- #
class Bench:
    """Content hashes for bench files, so drift is visible before it flatters."""

    @staticmethod
    def hashes():
        return {path.name: _sha(path.read_text(encoding="utf-8"))
                for path in sorted(BENCH.glob("*.json")) if path.name != "manifest.json"}

    @classmethod
    def seal(cls):
        current = cls.hashes()
        _write_json(BENCH_MANIFEST, {"sealed_at": time.time(), "files": current})
        return current

    @classmethod
    def drift(cls):
        sealed = (_read_json(BENCH_MANIFEST, {}) or {}).get("files") or {}
        if not sealed:
            return {"sealed": False, "changed": [], "added": [], "removed": []}
        current = cls.hashes()
        return {"sealed": True,
                "changed": sorted(name for name, value in current.items()
                                  if name in sealed and sealed[name] != value),
                "added": sorted(name for name in current if name not in sealed),
                "removed": sorted(name for name in sealed if name not in current)}


# --------------------------------------------------------------------------- #
# Prompt evolution: the lane may rewrite its own instructions, scored
# --------------------------------------------------------------------------- #
PROMPT_DEFAULTS = {
    "critic": (
        "You review a diff written by another agent for a local Python assistant. "
        'Return ONLY JSON: {"approve": true, "reasons": ["short reason"]}. '
        "Reject if the diff changes behaviour nobody asked for, weakens an error path, "
        "hardcodes a value that belongs in a test, or makes the code slower for no gain."
    ),
    "patcher": (
        "You produce minimal, surgical multi-hunk edits for a Python module. "
        "Preserve public signatures, respect # EVOLVE-BLOCK boundaries when present, "
        "and combine strengths of elite inspirations without introducing dead code."
    ),
    "planner": SUGGEST_SYSTEM,
    "breaker": (
        "You are an Adversarial QA Breaker for a Python module. Given surviving AST mutants "
        "and boundary conditions, return ONLY JSON edge-case held-out tests."
    ),
}


class PromptLab:
    """Overrides for the lane's own system prompts, so instructions can evolve too."""

    def __init__(self, path=None):
        self.path = Path(path or PROMPTS)

    def all(self):
        stored = _read_json(self.path, {})
        merged = dict(PROMPT_DEFAULTS)
        if isinstance(stored, dict):
            merged.update({key: value for key, value in stored.items() if isinstance(value, str)})
        return merged

    def get(self, key):
        return self.all().get(str(key), "")

    def set(self, key, value):
        clean = str(value or "").strip()
        if not clean:
            raise EvolutionError("A prompt override cannot be empty.")
        key = str(key or "").strip()
        if key not in PROMPT_DEFAULTS:
            raise EvolutionError(f"Unknown prompt key: {key or '(empty)'}.")
        stored = _read_json(self.path, {})
        stored = stored if isinstance(stored, dict) else {}
        stored[key] = clean[:6000]
        _write_json(self.path, stored)
        return {key: clean[:6000]}

    def reset(self, key):
        stored = _read_json(self.path, {})
        if isinstance(stored, dict) and key in stored:
            stored.pop(key)
            _write_json(self.path, stored)
        return self.all()


# --------------------------------------------------------------------------- #
# Sandbox: bubblewrap when present, plain child process otherwise
# --------------------------------------------------------------------------- #
def sandbox_available():
    return shutil.which("bwrap") is not None and os.environ.get("JARVIS_SANDBOX", "1") != "0"


def sandbox_refusal():
    """Why generated code must not run, or an empty string when it may.

    Returning bare argv when bwrap is missing ran model-generated Python with
    full user rights. Callers now refuse instead; a deployment that knowingly
    accepts that risk must set JARVIS_ALLOW_UNSANDBOXED_CODE=1.
    """
    if sandbox_available() or os.environ.get("JARVIS_ALLOW_UNSANDBOXED_CODE") == "1":
        return ""
    return ("The bwrap sandbox is unavailable; refusing to run generated code. "
            "Install bubblewrap or set JARVIS_ALLOW_UNSANDBOXED_CODE=1 to accept the risk.")


def hidden_home_paths(home=None):
    """Credential locations hidden from generated code and benchmark children.

    The sandbox mounts ``/`` read-only, which still exposes secrets to a
    *reader*. A generated skill could print ``~/.hermes/.env`` into its result.
    These paths are replaced by an empty tmpfs (directories) or /dev/null
    (files) after the root bind.
    """
    home = Path(home or Path.home())
    # Do NOT hide ~/.hermes itself: .venv/bin/python is a symlink into
    # ~/.hermes/tools, and hiding the directory would break every child.
    directories = (
        ".jarvis-tools", ".ssh", ".gnupg", ".password-store", ".aws", ".kube", ".docker",
        ".mozilla", ".config/google-chrome", ".config/chromium",
        ".config/google-chrome-for-testing", ".local/share/keyrings",
    )
    files = (".hermes/.env", ".hermes/.env.local", ".hermes/config.json",
             ".hermes/auth.json", ".hermes/credentials.json", ".hermes/secrets.json",
             ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".config/gh/hosts.yml")
    found_dirs = [home / name for name in directories if (home / name).is_dir()
                  and not (home / name).is_symlink()]
    found_files = [home / name for name in files if (home / name).is_file()
                   and not (home / name).is_symlink()]
    return found_dirs, found_files


def _ensure_tmpfs_parent_dirs(command: list[str], target: Path, hidden_dirs: list[Path]) -> None:
    """Create intermediate directories inside a hidden --tmpfs mount before re-binding an explicit child path."""
    for hdir in hidden_dirs:
        try:
            rel = target.relative_to(hdir)
        except ValueError:
            continue
        if len(rel.parts) > 1:
            command += ["--dir", str(target.parent)]
        return


def sandbox_argv(argv, writable=None, readonly=None, cwd=None):
    """Wrap *argv* so the child sees the tree read-only and no network.

    Not a VM and not a security boundary against a determined attacker, but it
    stops the common accidents: writes outside the temp HOME, network calls and
    reading the user's credentials. ``readonly`` entries (files or directories)
    are mounted read-only *after* ``--tmpfs /tmp`` so paths under the host /tmp
    stay visible to the child. ``cwd`` controls the working directory;
    verification runs with the live project tree read-only.
    """
    argv = list(argv)
    if not sandbox_available():
        return argv
    command = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
               "--tmpfs", "/tmp", "--unshare-net", "--unshare-pid", "--die-with-parent",
               "--chdir", str(cwd or ROOT)]
    hidden_dirs, hidden_files = hidden_home_paths()
    for directory in hidden_dirs:
        command += ["--tmpfs", str(directory)]
    for file_path in hidden_files:
        command += ["--ro-bind", "/dev/null", str(file_path)]
    if writable is not None:
        wpath = Path(str(writable))
        _ensure_tmpfs_parent_dirs(command, wpath, hidden_dirs)
        command += ["--bind", str(wpath), str(wpath)]
    for extra in readonly or ():
        if str(extra):
            epath = Path(str(extra))
            _ensure_tmpfs_parent_dirs(command, epath, hidden_dirs)
            command += ["--ro-bind", str(epath), str(epath)]
    return command + argv


# --------------------------------------------------------------------------- #
# Runtime watch: catch the exception that the tests never saw
# --------------------------------------------------------------------------- #
WATCH_STATE = STATE / "watch.json"
WATCH_LOG = STATE / "watch.log"
TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\):")


def extract_tracebacks(text: str, limit: int = 5) -> list[str]:
    """Cut blocks that start at a Traceback header and end at the last frame line."""
    blocks, current = [], []
    for line in str(text or "").splitlines():
        if TRACEBACK_RE.search(line):
            if current:
                blocks.append("\n".join(current))
            current = [line]
            continue
        if current:
            if line.startswith((" ", "\t")) or not line.strip():
                current.append(line)
            else:
                current.append(line)
                blocks.append("\n".join(current))
                current = []
    if current:
        blocks.append("\n".join(current))
    return [block.strip() for block in blocks if "line " in block][-limit:]


class RuntimeWatch:
    """Scan the service journal for production tracebacks and de-duplicate them.

    Tests cover what we thought of; the journal covers what actually happened.
    The watcher only *proposes* and records; applying stays behind the token,
    unless ``auto_apply`` is on for a module with a benchmark.
    """

    def __init__(self, state: Path | None = None, log: Path | None = None,
                 unit: str = "jarvis.service"):
        self.state_path = Path(state or WATCH_STATE)
        self.log_path = Path(log or WATCH_LOG)
        self.unit = unit

    def state(self) -> dict:
        value = _read_json(self.state_path, {})
        return value if isinstance(value, dict) else {}

    def save_state(self, **patch) -> dict:
        current = {**self.state(), **patch}
        _write_json(self.state_path, current)
        return current

    def seen(self) -> set[str]:
        return set(self.state().get("seen") or [])

    def scan(self, lines: int = 800) -> list[dict]:
        """Return fresh, de-duplicated tracebacks with the module they point at."""
        try:
            done = subprocess.run(["journalctl", "--user", "-u", self.unit, "-n", str(lines),
                                   "-o", "cat", "--no-pager"],
                                  capture_output=True, text=True, timeout=25)
        except (OSError, subprocess.TimeoutExpired) as error:
            return [{"error": str(error)[:200]}]
        found = []
        seen = self.seen()
        new_seen = set(seen)
        for block in extract_tracebacks(done.stdout):
            digest = _sha(" ".join(block.split()))[:16]
            if digest in new_seen:
                continue
            new_seen.add(digest)
            modules = re.findall(r'File "([^"]+\.py)", line (\d+)', block)
            module = ""
            for path, _line in reversed(modules):
                if "site-packages" in path or "/.venv/" in path:
                    continue
                candidate = Path(path).stem
                if (ROOT / f"{candidate}.py").is_file():
                    module = candidate
                    break
            found.append({"id": digest, "module": module, "traceback": block[-4000:]})
        self.save_state(seen=sorted(new_seen)[-400:], last_scan=time.time(), last_count=len(found))
        return found

    def tail(self, limit: int = 20) -> list[dict]:
        try:
            rows = [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()[-limit:]]
            return [row for row in rows if isinstance(row, dict)]
        except (OSError, ValueError):
            return []

    def record(self, row: dict) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({**row, "ts": time.time()}, ensure_ascii=False, default=str)[:4000] + "\n")
        except OSError:
            pass
