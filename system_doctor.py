"""Self-healing system doctor & integrity verifier (`system_doctor.py`) for Jarvis.

Performs deterministic diagnostics and optional automatic remediation (`auto_heal=True`):
  1. SQLite `PRAGMA quick_check` across `episodic_memory`, `semantic_cache`, and `code_index`
     databases (quarantining corrupted DB files as `.corrupt-<ts>` when `auto_heal=True`).
  2. Permission hardening (`0700` state dirs, `0600` ledgers & SQLite databases).
  3. Orphaned `.tmp-*` atomic-write cleanup (files older than `stale_seconds`).
  4. Idle in-RAM cache release (`code_index.evict_idle_cache(force=True)`).
  5. Unified `health_score` (`0..100`) combining SQLite, thermal/RAM, Viewer QA, and Security gates.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import time
from pathlib import Path

import agent_cli
import code_index
import hardware_guard
import qa_gate
import security_scanner

SENSITIVE_STATE_FILES = (
    "budget_ledger.json",
    "episodic_memory.sqlite3",
    "semantic_cache.sqlite3",
)


def _state_root() -> Path:
    base = agent_cli.ROOT.parent
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base


def _check_sqlite_file(db_path: Path, *, auto_heal: bool) -> dict:
    if not db_path.is_file():
        return {"path": db_path.name, "present": False, "ok": True, "healed": False}
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        try:
            row = conn.execute("PRAGMA quick_check(1)").fetchone()
            verdict = str(row[0] if row else "").strip().lower()
        finally:
            conn.close()
        if verdict == "ok":
            return {"path": db_path.name, "present": True, "ok": True, "healed": False}
    except sqlite3.DatabaseError as exc:
        verdict = f"corrupt: {exc}"

    healed = False
    if auto_heal:
        quarantine = db_path.with_name(f"{db_path.name}.corrupt-{int(time.time())}")
        try:
            db_path.replace(quarantine)
            for suffix in ("-wal", "-shm"):
                sidecar = db_path.with_name(db_path.name + suffix)
                if sidecar.exists():
                    sidecar.unlink()
            healed = True
        except OSError:
            healed = False
    return {
        "path": db_path.name,
        "present": True,
        "ok": healed,
        "healed": healed,
        "detail": verdict,
    }


def _heal_permissions(state_dir: Path, *, auto_heal: bool) -> tuple[list[str], list[str]]:
    issues: list[str] = []
    healed: list[str] = []

    try:
        dir_mode = stat.S_IMODE(state_dir.stat().st_mode)
        if dir_mode & 0o077:
            if auto_heal:
                os.chmod(state_dir, 0o700)
                healed.append(f"chmod 0700 {state_dir.name}")
            else:
                issues.append(f"Zbyt szerokie uprawnienia katalogu {state_dir.name}: {oct(dir_mode)}")
    except OSError:
        pass

    for fname in SENSITIVE_STATE_FILES:
        fpath = state_dir / fname
        if not fpath.is_file():
            continue
        try:
            fmode = stat.S_IMODE(fpath.stat().st_mode)
            if fmode & 0o077:
                if auto_heal:
                    os.chmod(fpath, 0o600)
                    healed.append(f"chmod 0600 {fname}")
                else:
                    issues.append(f"Zbyt szerokie uprawnienia pliku {fname}: {oct(fmode)}")
        except OSError:
            continue

    return issues, healed


def _sweep_stale_temps(state_dir: Path, *, stale_seconds: float, auto_heal: bool) -> tuple[int, int]:
    now = time.time()
    found = 0
    removed = 0
    for dirpath, _dirnames, filenames in os.walk(state_dir):
        for fname in filenames:
            if ".tmp-" not in fname and not fname.startswith(".tmp"):
                continue
            fpath = Path(dirpath) / fname
            try:
                age = now - fpath.stat().st_mtime
            except OSError:
                continue
            if age >= stale_seconds:
                found += 1
                if auto_heal:
                    try:
                        fpath.unlink()
                        removed += 1
                    except OSError:
                        pass
    return found, removed


def run_diagnostics(*, project_dir: str | Path | None = None,
                    auto_heal: bool = True,
                    stale_temp_seconds: float = 3600.0) -> dict:
    """Run full Jarvis health inspection, optional self-healing, and compute 0..100 score."""
    state_dir = _state_root()
    healed_actions: list[str] = []
    issues: list[str] = []
    score = 100

    # 1. SQLite integrity across core databases + code_index DBs
    db_candidates = [state_dir / "episodic_memory.sqlite3", state_dir / "semantic_cache.sqlite3"]
    idx_dir = state_dir / "code_index"
    if idx_dir.is_dir():
        db_candidates.extend(sorted(idx_dir.glob("*.sqlite3"))[:10])

    sqlite_results: list[dict] = []
    for dbp in db_candidates:
        res = _check_sqlite_file(dbp, auto_heal=auto_heal)
        sqlite_results.append(res)
        if res.get("healed"):
            healed_actions.append(f"kwarantanna uszkodzonej bazy {res['path']}")
        elif not res.get("ok"):
            score -= 25
            issues.append(f"Uszkodzona baza SQLite: {res['path']}")

    # 2. Permissions hardening
    perm_issues, perm_healed = _heal_permissions(state_dir, auto_heal=auto_heal)
    healed_actions.extend(perm_healed)
    if perm_issues:
        score -= 10 * len(perm_issues)
        issues.extend(perm_issues)

    # 3. Stale atomic `.tmp-*` sweep
    stale_found, stale_removed = _sweep_stale_temps(
        state_dir, stale_seconds=max(1.0, float(stale_temp_seconds)), auto_heal=auto_heal
    )
    if stale_removed:
        healed_actions.append(f"usunięto {stale_removed} osieroconych plików .tmp")
    elif stale_found:
        score -= 5
        issues.append(f"Wykryto {stale_found} starych plików tymczasowych .tmp")

    # 4. Evict idle in-RAM caches when healing
    evicted_caches = code_index.evict_idle_cache(force=True) if auto_heal else 0
    if evicted_caches:
        healed_actions.append(f"zwolniono {evicted_caches} buforów indeksu z RAM")

    # 5. Hardware thermal & RAM pressure snapshot
    hw = hardware_guard.snapshot()
    if hw["state"] == "critical":
        score -= 25
        issues.extend(hw["reasons"])
    elif hw["state"] == "warm":
        score -= 10
        issues.extend(hw["reasons"])

    # 6. Optional project-level QA, SRI & security audit
    viewer_qa = None
    sec_scan = None
    sri_res = None
    if project_dir:
        proj = Path(project_dir).expanduser().resolve()
        if (proj / "viewer" / "index.html").is_file():
            import change_impact
            sri_res = change_impact.sync_viewer_sri(proj, fix=auto_heal)
            if sri_res.get("updated"):
                healed_actions.append(f"zaktualizowano {sri_res['updated']} sum sha384 SRI w viewer/index.html")
            elif not sri_res.get("ok"):
                score -= 20
                issues.append(f"Niezgodność sum SRI sha384 w viewer/index.html ({len(sri_res.get('mismatches') or [])}).")
            viewer_qa = qa_gate.audit_viewer(proj)
            if not viewer_qa.get("ok"):
                score -= 20
                issues.extend(viewer_qa.get("issues") or [])
        if proj.is_dir():
            sec_scan = security_scanner.scan_directory(proj, include_tests=False)
            if not sec_scan.get("ok"):
                score -= 25
                issues.append(f"Skaner bezpieczeństwa wykrył {sec_scan['findings_count']} zagrożeń.")

    final_score = max(0, min(100, score))
    return {
        "ok": final_score >= 70 and not any("Uszkodzona baza" in i for i in issues),
        "checked_at": round(time.time(), 3),
        "health_score": final_score,
        "auto_heal": auto_heal,
        "healed_actions": healed_actions,
        "issues": issues,
        "sqlite": sqlite_results,
        "stale_temps_found": stale_found,
        "hardware": hw,
        "sri_ok": sri_res.get("ok") if isinstance(sri_res, dict) else None,
        "viewer_qa_ok": viewer_qa.get("ok") if isinstance(viewer_qa, dict) else None,
        "security_ok": sec_scan.get("ok") if isinstance(sec_scan, dict) else None,
    }
