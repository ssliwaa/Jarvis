"""Self-healing log watchdog for jarvis.service using sandboxed repair runs.

Scans `journalctl --user -u jarvis.service` (or supplied log text) for repeated
Python tracebacks (`>= threshold` occurrences in a sliding window), deduplicates
incidents by normalized stack signature, and optionally dispatches the healthiest
agent via `agent_router` + `code_index` to prepare a fix and unit test inside
`outbox/` — never modifying live production files directly.
"""

import fcntl
import hashlib
import json
import os
import re
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

import agent_cli
import agent_router
import code_index

TRACEBACK_START_RE = re.compile(r'Traceback \(most recent call last\):')
EXCEPTION_LINE_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Warning|Fault))(?::\s*(.*))?$')
FILE_LINE_RE = re.compile(r'File "([^"]+)", line (\d+), in ([A-Za-z0-9_<>]+)')
HEX_ADDR_RE = re.compile(r'0x[0-9a-fA-F]+')
DEFAULT_COOLDOWN_SEC = 3600


def _state_path() -> Path:
    return agent_cli.ROOT.parent / 'watchdog_state.json'


@contextmanager
def _state_lock():
    base = agent_cli.ROOT.parent
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(base / '.watchdog.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _load_state() -> dict:
    path = _state_path()
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(state: dict) -> None:
    path = _state_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding='utf-8')
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def fetch_service_logs(window_minutes: int = 10, service: str = 'jarvis.service') -> str:
    """Read recent systemd user service logs without blocking."""
    mins = max(1, min(int(window_minutes or 10), 180))
    try:
        res = subprocess.run(
            ['journalctl', '--user', '-u', service, '--since', f'{mins} minutes ago', '--no-pager', '-n', '600'],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return res.stdout or ''
    except (OSError, subprocess.SubprocessError):
        # OSError: journalctl missing on this box; SubprocessError: the
        # 10 s timeout fired — either way the scan just sees no new logs.
        return ''


def _strip_journal_prefix(line: str) -> str:
    # journalctl lines often start with "Nov 13 20:01:02 host python[1234]: "
    idx = line.find(']: ')
    if 0 < idx < 64:
        return line[idx + 3:]
    return line


def parse_tracebacks(log_text: str) -> list[dict]:
    """Extract and fingerprint Python tracebacks from raw log lines."""
    if not isinstance(log_text, str) or not log_text.strip():
        return []

    clean_lines = [_strip_journal_prefix(ln.rstrip()) for ln in log_text.splitlines()]
    found = []
    i = 0
    n = len(clean_lines)

    while i < n:
        if not TRACEBACK_START_RE.search(clean_lines[i]):
            i += 1
            continue
        block = [clean_lines[i].strip()]
        frames = []
        exc_type = 'Exception'
        exc_msg = ''
        i += 1
        while i < n and len(block) < 45:
            cur = clean_lines[i]
            stripped = cur.strip()
            fm = FILE_LINE_RE.search(stripped)
            if fm:
                frames.append((fm.group(1), int(fm.group(2)), fm.group(3)))
                block.append(stripped)
                i += 1
                continue
            em = EXCEPTION_LINE_RE.match(stripped)
            if em and frames:
                exc_type = em.group(1)
                exc_msg = (em.group(2) or '').strip()
                block.append(stripped)
                i += 1
                break
            if stripped.startswith(('Traceback ', '---')) and frames:
                break
            block.append(stripped)
            i += 1

        if not frames:
            continue

        top_file, top_line, top_func = frames[-1]
        norm_frames = '|'.join(f'{Path(f).name}:{fn}' for f, _ln, fn in frames[-4:])
        norm_exc = HEX_ADDR_RE.sub('0xADDR', f'{exc_type}:{ norm_frames }')
        sig = hashlib.sha256(norm_exc.encode('utf-8')).hexdigest()[:12]

        found.append({
            'signature': sig,
            'error_type': exc_type,
            'message': exc_msg[:240],
            'file': top_file,
            'line': top_line,
            'function': top_func,
            'traceback': '\n'.join(block)[-2500:],
        })

    return found


def scan_logs(log_text: str | None = None, window_minutes: int = 10,
              threshold: int = 3, auto_repair: bool = False,
              project_root: str | Path | None = None) -> dict:
    """Detect repeated exceptions (`>= threshold`) and optionally launch a sandboxed repair agent."""
    raw = log_text if log_text is not None else fetch_service_logs(window_minutes=window_minutes)
    occurrences = parse_tracebacks(raw)
    grouped: dict[str, dict] = {}
    for item in occurrences:
        sig = item['signature']
        if sig not in grouped:
            grouped[sig] = {**item, 'count': 1}
        else:
            grouped[sig]['count'] += 1

    min_hits = max(1, int(threshold or 3))
    incidents = [g for g in grouped.values() if g['count'] >= min_hits]
    incidents.sort(key=lambda x: x['count'], reverse=True)

    now = round(time.time(), 3)
    dispatched = []

    with _state_lock():
        state = _load_state()
        known = dict(state.get('incidents') or {})
        for inc in incidents:
            sig = inc['signature']
            prev = known.get(sig) or {}
            known[sig] = {
                **inc,
                'last_seen': now,
                'repair_run_id': prev.get('repair_run_id', ''),
                'repair_agent': prev.get('repair_agent', ''),
                'repaired_at': prev.get('repaired_at', 0),
            }
        state['incidents'] = known
        state['last_scan_at'] = now
        _save_state(state)

    if auto_repair and incidents:
        for inc in incidents[:1]:
            sig = inc['signature']
            state = _load_state()
            stored = (state.get('incidents') or {}).get(sig) or {}
            if now - float(stored.get('repaired_at') or 0) < DEFAULT_COOLDOWN_SEC:
                continue
            rep = dispatch_sandbox_repair(sig, project_root=project_root)
            if rep.get('ok'):
                dispatched.append(rep)

    return {
        'ok': True,
        'scanned_tracebacks': len(occurrences),
        'incidents': incidents,
        'dispatched': dispatched,
    }


def dispatch_sandbox_repair(signature: str, project_root: str | Path | None = None,
                            agent_id: str = '') -> dict:
    """Launch a read-only bwrap agent run to prepare a patch + regression test in outbox/."""
    state = _load_state()
    incidents = state.get('incidents') or {}
    inc = incidents.get(str(signature or '').strip())
    if not isinstance(inc, dict):
        raise ValueError(f'Unknown incident signature: {signature!r}')

    chosen = str(agent_id or '').strip().lower() or agent_router.pick_best_agent(
        role='repair',
        task=f"Napraw wyjątek {inc.get('error_type')} w {inc.get('file')}",
        require_idle=True,
    )
    if not chosen:
        return {'ok': False, 'signature': signature, 'error': 'Brak wolnego zainstalowanego agenta do naprawy.'}

    proj_dir = Path(project_root or Path(__file__).resolve().parent).expanduser().resolve()
    ctx_pack = code_index.build_context_pack(
        f"{inc.get('error_type')} {Path(inc.get('file', '')).name} {inc.get('function', '')}",
        root_dir=proj_dir,
        limit=5,
    )

    task = (
        f"[WATCHDOG SAMONAPRAWA — sygnatura `{signature}`]\n"
        f"W usłudze Jarvisa powtórzył się wyjątek `{inc.get('error_type')}` ({inc.get('count')}x):\n"
        f"- Plik: `{inc.get('file')}` (linia {inc.get('line')}, funkcja `{inc.get('function')}`)\n\n"
        f"```text\n{inc.get('traceback', '')}\n```\n\n"
        f"{ctx_pack}\n\n"
        f"Twoje zadanie:\n"
        f"1. Odczytaj wskazany plik z `{proj_dir}` (masz dostęp read-only).\n"
        f"2. Przygotuj poprawioną wersję pliku w swoim `outbox/` (zachowując ścieżkę względną względem `{proj_dir}`).\n"
        f"3. Dodaj test regresyjny w `outbox/tests/` potwierdzający usunięcie usterki.\n"
        f"4. Opisz przyczynę i rozwiązanie w `outbox/outbox.md`."
    )

    started = agent_cli.start_async(
        chosen,
        task,
        approved=True,
        consent='watchdog',
        target_hint=str(proj_dir),
        task_label=f"[watchdog:{signature}] Naprawa {inc.get('error_type')} w {Path(inc.get('file', '')).name}",
    )

    now = round(time.time(), 3)
    with _state_lock():
        st = _load_state()
        incs = dict(st.get('incidents') or {})
        if signature in incs:
            incs[signature]['repair_agent'] = chosen
            incs[signature]['repair_run_id'] = started['id']
            incs[signature]['repaired_at'] = now
            st['incidents'] = incs
            _save_state(st)

    return {
        'ok': True,
        'signature': signature,
        'agent': chosen,
        'run_id': started['id'],
        'outbox_hint': f'Po zakończeniu przejrzyj diff i wdróż przez apply_outbox({chosen!r}, {str(proj_dir)!r}).',
    }


def watchdog_status() -> dict:
    """Return recorded watchdog incidents and last scan timestamp."""
    state = _load_state()
    incidents = list((state.get('incidents') or {}).values())
    incidents.sort(key=lambda x: float(x.get('last_seen') or 0), reverse=True)
    return {
        'ok': True,
        'last_scan_at': state.get('last_scan_at'),
        'incidents': incidents[:25],
    }
