"""Desktop & Operator workflow pattern miner and 1-click macro compiler for Jarvis.

1. `record_event`: appends structured user/operator actions (`clipboard.read`,
   `ocr.extract`, `notes.save`, `app.focus`, `browser.open`, etc.) to a bounded JSONL log.
2. `mine_patterns`: discovers recurring contiguous action n-grams (`length 2..5`)
   that appear at least `min_support` times without overlapping.
3. `compile_macro`: turns a mined pattern into an AST-validated, callable Python
   macro module and registers it in `macros.json` for voice/UI invocation.
"""

from __future__ import annotations

import ast
import fcntl
import hashlib
import json
import os
import re
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import agent_cli

MAX_EVENTS = 1500
SAFE_MACRO_RE = re.compile(r"^[a-z][a-z0-9_]{1,48}$")


def _workflows_dir() -> Path:
    d = agent_cli.ROOT.parent / "workflows"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def _events_path() -> Path:
    return _workflows_dir() / "events.jsonl"


def _macros_path() -> Path:
    return _workflows_dir() / "macros.json"


@contextmanager
def _workflow_lock():
    base = _workflows_dir()
    fd = os.open(base / ".workflow.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}-{time.time_ns()}")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def record_event(kind: str, target: str = "", params: dict | None = None) -> dict:
    """Record one atomic desktop/operator action in `events.jsonl`."""
    clean_kind = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(kind or "").strip().lower()).strip("_")
    if not clean_kind:
        raise ValueError("kind is required")
    entry = {
        "ts": round(time.time(), 3),
        "kind": clean_kind[:64],
        "target": str(target or "").strip()[:160],
        "params": params if isinstance(params, dict) else {},
    }
    epath = _events_path()
    with _workflow_lock():
        with epath.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        try:
            os.chmod(epath, 0o600)
            lines = epath.read_text(encoding="utf-8").splitlines()
            if len(lines) > MAX_EVENTS:
                _atomic_write_text(epath, "\n".join(lines[-MAX_EVENTS:]) + "\n")
        except OSError:
            pass
    return entry


def read_events(limit: int = 500) -> list[dict]:
    epath = _events_path()
    if not epath.is_file():
        return []
    rows = []
    for line in epath.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict) and item.get("kind"):
                rows.append(item)
        except ValueError:
            continue
    return rows


def _step_token(event: dict) -> str:
    kind = str(event.get("kind") or "")
    target = str(event.get("target") or "")
    return f"{kind}:{target}" if target else kind


def _pattern_id(steps: tuple[str, ...]) -> str:
    return hashlib.sha256(" -> ".join(steps).encode("utf-8")).hexdigest()[:10]


def mine_patterns(min_len: int = 2, max_len: int = 4, min_support: int = 2) -> list[dict]:
    """Find non-overlapping recurring n-grams of actions ordered by (support * length)."""
    events = read_events(limit=MAX_EVENTS)
    tokens = [_step_token(e) for e in events]
    n_total = len(tokens)
    if n_total < min_len * min_support:
        return []

    found: dict[tuple[str, ...], dict] = {}
    for k in range(max(2, int(min_len)), min(6, int(max_len)) + 1):
        i = 0
        positions_by_seq: dict[tuple[str, ...], list[int]] = {}
        while i <= n_total - k:
            seq = tuple(tokens[i:i + k])
            if len(set(seq)) == 1:
                i += 1
                continue
            prev_positions = positions_by_seq.setdefault(seq, [])
            if not prev_positions or i >= prev_positions[-1] + k:
                prev_positions.append(i)
            i += 1

        for seq, pos_list in positions_by_seq.items():
            if len(pos_list) >= int(min_support):
                pid = _pattern_id(seq)
                last_idx = pos_list[-1]
                sample_events = events[last_idx:last_idx + k]
                found[seq] = {
                    "id": pid,
                    "steps": list(seq),
                    "length": k,
                    "support": len(pos_list),
                    "score": len(pos_list) * k,
                    "title": " → ".join(seq),
                    "sample_steps": [
                        {"kind": e["kind"], "target": e.get("target", ""), "params": e.get("params") or {}}
                        for e in sample_events
                    ],
                }

    ranked = sorted(found.values(), key=lambda r: (r["score"], r["support"], r["length"]), reverse=True)
    return ranked[:20]


def list_macros() -> list[dict]:
    try:
        data = json.loads(_macros_path().read_text(encoding="utf-8"))
        return [m for m in data if isinstance(m, dict)] if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def compile_macro(pattern_id: str, name: str = "", output_dir: str | Path | None = None) -> dict:
    """Compile a mined pattern into an AST-validated Python macro file and register it."""
    patterns = mine_patterns(min_len=2, max_len=5, min_support=2)
    chosen = next((p for p in patterns if p["id"] == pattern_id), None)
    if chosen is None:
        raise ValueError(f"Nie znaleziono wzorca makra o ID: {pattern_id}")

    raw_name = re.sub(r"[^a-z0-9_]+", "_", str(name or f"workflow_{pattern_id[:6]}").lower()).strip("_")
    if not raw_name or not raw_name[0].isalpha():
        raw_name = f"macro_{raw_name}"
    macro_name = raw_name[:48]
    if not SAFE_MACRO_RE.match(macro_name):
        raise ValueError(f"Nieprawidłowa nazwa makra: {name!r}")

    dest_dir = Path(output_dir) if output_dir else (_workflows_dir() / "compiled")
    dest_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    dest_file = dest_dir / f"{macro_name}.py"

    steps_json = json.dumps(chosen["sample_steps"], ensure_ascii=False, indent=4)
    code = (
        f'"""Auto-compiled Jarvis desktop workflow macro: {chosen["title"]}."""\n\n'
        f"STEPS = {steps_json}\n\n\n"
        f"def run_macro(executor=None, dry_run: bool = False) -> dict:\n"
        f'    """Execute or preview the {len(chosen["sample_steps"])}-step macro `{macro_name}`."""\n'
        f"    executed = []\n"
        f"    for idx, step in enumerate(STEPS, 1):\n"
        f"        if not dry_run and callable(executor):\n"
        f"            res = executor(step['kind'], step.get('target', ''), step.get('params') or {{}})\n"
        f"            executed.append({{'step': idx, 'kind': step['kind'], 'result': res}})\n"
        f"        else:\n"
        f"            executed.append({{'step': idx, 'kind': step['kind'], 'target': step.get('target', ''), 'dry_run': True}})\n"
        f"    return {{'ok': True, 'macro': {macro_name!r}, 'steps': executed}}\n"
    )
    ast.parse(code, filename=str(dest_file))
    _atomic_write_text(dest_file, code)

    record = {
        "name": macro_name,
        "pattern_id": pattern_id,
        "title": chosen["title"],
        "support": chosen["support"],
        "steps": chosen["sample_steps"],
        "file": str(dest_file),
        "created_at": round(time.time(), 3),
    }
    with _workflow_lock():
        macros = [m for m in list_macros() if m.get("name") != macro_name]
        macros.append(record)
        _atomic_write_text(_macros_path(), json.dumps(macros, indent=2, ensure_ascii=False))
    return {"ok": True, "macro": record}
