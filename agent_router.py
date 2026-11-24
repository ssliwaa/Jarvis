"""Adaptive agent router, budget-aware tier selector, and API circuit-breaker for Jarvis.

Combines empirical run history (`runs.json`), role specialization priors, live
busy-state checks, cloud budget state (`budget_guard`: auto-economy shift at >=80%,
paid cloud block at >=100%), and automatic cooldowns (`429 quota_exceeded`,
`auth_failed`, `model_rejected`).
"""

import fcntl
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path

import agent_cli

DEFAULT_COOLDOWN_SECONDS = {
    'quota_exceeded': 900,   # 15 minutes on HTTP 429 / exhausted quota
    'auth_failed': 1800,     # 30 minutes on invalid/expired API key
    'model_rejected': 600,   # 10 minutes on rejected model/reasoning flag
}

ROLE_PRIORS = {
    'architect': {'claude': 0.92, 'antigravity': 0.86, 'hermes': 0.82, 'opencode': 0.78},
    'backend': {'claude': 0.90, 'hermes': 0.88, 'opencode': 0.84, 'antigravity': 0.82},
    'frontend': {'claude': 0.90, 'antigravity': 0.88, 'opencode': 0.83, 'hermes': 0.80},
    'qa': {'hermes': 0.88, 'opencode': 0.86, 'claude': 0.88, 'antigravity': 0.82},
    'reviewer': {'claude': 0.92, 'antigravity': 0.87, 'hermes': 0.84, 'opencode': 0.82},
    'repair': {'claude': 0.91, 'hermes': 0.87, 'opencode': 0.84, 'antigravity': 0.83},
    'general': {'claude': 0.90, 'hermes': 0.86, 'antigravity': 0.85, 'opencode': 0.82},
}

ECONOMY_AGENTS = {'opencode', 'hermes', 'antigravity'}
METERED_PREMIUM_AGENTS = {'claude'}

ROLE_KEYWORDS = (
    ('frontend', ('css', 'html', 'ui', 'ux', 'react', 'widok', 'interfejs', 'viewer', 'styl', 'przycisk')),
    ('qa', ('test', 'unittest', 'pytest', 'regresj', 'lint', 'qa', 'weryfikacj')),
    ('architect', ('architektur', 'plan', 'projekt', 'struktur', 'kontrakt', 'refaktor')),
    ('repair', ('napraw', 'traceback', 'wyjątek', 'exception', 'bug', 'błąd', 'crash', 'fix')),
    ('backend', ('api', 'endpoint', 'sqlite', 'baza', 'serwer', 'daemon', 'cli', 'bwrap')),
)


def _state_path() -> Path:
    return agent_cli.ROOT / 'router_state.json'


@contextmanager
def _state_lock():
    base = agent_cli.ROOT
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(base / '.router.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
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
    tmp = path.with_name(f'.{path.name}.tmp-{os.getpid()}-{os.urandom(4).hex()}-{time.time_ns()}')
    try:
        tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding='utf-8')
        os.chmod(tmp, 0o600)
        tmp.replace(path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _budget_snapshot() -> dict:
    try:
        import budget_guard
        return budget_guard.status()
    except Exception:
        return {'state': 'healthy', 'utilization_ratio': 0.0}


def infer_role(task: str) -> str:
    """Infer specialization role from task description."""
    lower = str(task or '').lower()
    for role, words in ROLE_KEYWORDS:
        if any(w in lower for w in words):
            return role
    return 'general'


def trip_circuit(agent_id: str, error_kind: str, error_hint: str = '',
                 cooldown_seconds: int | None = None) -> dict:
    """Put an agent into temporary circuit-breaker quarantine after API/auth failure."""
    agent_cli._agent(agent_id)
    duration = int(
        cooldown_seconds
        if cooldown_seconds is not None
        else DEFAULT_COOLDOWN_SECONDS.get(error_kind, 300)
    )
    duration = max(10, min(duration, 7200))
    now = round(time.time(), 3)
    entry = {
        'agent': agent_id,
        'error_kind': str(error_kind or 'unknown'),
        'error_hint': str(error_hint or '')[:240],
        'tripped_at': now,
        'until': round(now + duration, 3),
    }
    with _state_lock():
        state = _load_state()
        circuits = dict(state.get('circuits') or {})
        circuits[agent_id] = entry
        state['circuits'] = circuits
        _save_state(state)
    try:
        import event_bus
        event_bus.publish('router.circuit_tripped', entry)
    except Exception:
        pass
    return entry


def clear_circuit(agent_id: str) -> bool:
    """Clear circuit-breaker cooldown (e.g. after a successful run or config update)."""
    agent_cli._agent(agent_id)
    with _state_lock():
        state = _load_state()
        circuits = dict(state.get('circuits') or {})
        existed = agent_id in circuits
        circuits.pop(agent_id, None)
        state['circuits'] = circuits
        _save_state(state)
    if existed:
        try:
            import event_bus
            event_bus.publish('router.circuit_cleared', {'agent': agent_id})
        except Exception:
            pass
    return existed


def record_run_outcome(agent_id: str, record: dict) -> None:
    """Update circuit-breaker and cumulative telemetry from a finished run record."""
    if not isinstance(record, dict):
        return
    status = record.get('status')
    err_kind = str(record.get('error_kind') or '')
    err_hint = str(record.get('error_hint') or '')
    if status == 'done':
        clear_circuit(agent_id)
    elif err_kind in DEFAULT_COOLDOWN_SECONDS:
        trip_circuit(agent_id, err_kind, err_hint)


def active_circuits() -> dict[str, dict]:
    """Return currently open (quarantined) agent circuits."""
    now = time.time()
    state = _load_state()
    raw = state.get('circuits') or {}
    if not isinstance(raw, dict):
        return {}
    out = {}
    for aid, info in raw.items():
        if not isinstance(info, dict):
            continue
        until = float(info.get('until') or 0)
        if until > now:
            out[aid] = {
                **info,
                'remaining_seconds': round(until - now, 1),
            }
    return out


def _empirical_metrics(agent_id: str) -> dict:
    history = agent_cli.runs(agent_id)[-25:]
    finished = [r for r in history if isinstance(r, dict) and r.get('status') in ('done', 'failed', 'timeout')]
    if not finished:
        return {'runs': 0, 'success_rate': None, 'avg_seconds': None}
    wins = sum(1 for r in finished if r.get('status') == 'done')
    durations = [float(r['seconds']) for r in finished if isinstance(r.get('seconds'), (int, float)) and r['seconds'] > 0]
    return {
        'runs': len(finished),
        'success_rate': round(wins / len(finished), 3),
        'avg_seconds': round(sum(durations) / len(durations), 1) if durations else None,
    }


def rank_agents(role: str = '', task: str = '', exclude=None,
                require_idle: bool = False, allow_quarantined: bool = False,
                allow_budget_override: bool = False) -> list[dict]:
    """Score and sort all agents for a given role/task, factoring in live cloud budget state."""
    eff_role = (role or infer_role(task) or 'general').strip().lower()
    priors = ROLE_PRIORS.get(eff_role) or ROLE_PRIORS['general']
    excluded = {str(x).strip().lower() for x in (exclude or ()) if x}
    circuits = active_circuits()
    bstate = _budget_snapshot().get('state') or 'healthy'

    ranked = []
    for aid in agent_cli.agent_ids():
        if aid in excluded:
            continue
        installed = agent_cli.binary_present(aid)
        busy, _ = agent_cli._check_running(aid)
        circuit = circuits.get(aid)
        metrics = _empirical_metrics(aid)

        prior = float(priors.get(aid, 0.80))
        emp = metrics['success_rate']
        n = metrics['runs']
        blended = ((prior * 4.0) + ((emp if emp is not None else prior) * n)) / (4.0 + n)

        avg_s = metrics['avg_seconds']
        speed_bonus = 0.04 * max(0.0, 1.0 - (min(avg_s, 300.0) / 300.0)) if avg_s is not None else 0.01
        score = round(blended + speed_bonus, 4)

        budget_blocked = False
        if bstate in ('soft_cap', 'warning') and not allow_budget_override:
            if aid in ECONOMY_AGENTS:
                score = round(score + 0.06, 4)
            elif aid in METERED_PREMIUM_AGENTS and eff_role != 'architect':
                score = round(score - 0.08, 4)
        elif bstate in ('hard_cap', 'capped') and not allow_budget_override:
            if aid in METERED_PREMIUM_AGENTS:
                budget_blocked = True
                score = round(score - 0.60, 4)
            elif aid in ECONOMY_AGENTS:
                score = round(score + 0.08, 4)

        eligible = (
            installed
            and (not busy if require_idle else True)
            and (allow_quarantined or circuit is None)
            and not budget_blocked
        )
        if circuit is not None:
            score = round(score - 0.50, 4)
        if busy and require_idle:
            score = round(score - 0.35, 4)
        if not installed:
            score = -1.0

        ranked.append({
            'agent': aid,
            'role': eff_role,
            'score': score,
            'eligible': eligible,
            'installed': installed,
            'busy': busy,
            'quarantined': circuit is not None,
            'budget_blocked': budget_blocked,
            'budget_state': bstate,
            'circuit': circuit,
            'metrics': metrics,
        })

    ranked.sort(key=lambda r: (r['eligible'], r['installed'], r['score']), reverse=True)
    return ranked


def pick_best_agent(role: str = '', task: str = '', exclude=None,
                    require_idle: bool = True,
                    allow_budget_override: bool = False) -> str:
    """Return the best available agent ID (respecting budget caps and circuit breakers)."""
    candidates = rank_agents(
        role=role, task=task, exclude=exclude,
        require_idle=require_idle, allow_quarantined=False,
        allow_budget_override=allow_budget_override,
    )
    for row in candidates:
        if row['eligible']:
            return row['agent']
    fallback = rank_agents(
        role=role, task=task, exclude=exclude,
        require_idle=require_idle, allow_quarantined=True,
        allow_budget_override=allow_budget_override,
    )
    for row in fallback:
        if row['installed'] and not row['budget_blocked'] and (not row['busy'] if require_idle else True):
            return row['agent']
    return ''


def select_team(goal: str, max_members: int = 3, roles: list[str] | None = None) -> list[dict]:
    """Select an optimal multi-agent roster for a collaborative project."""
    desired_roles = list(roles or ('architect', 'backend', 'frontend', 'qa'))[:max(1, min(int(max_members or 3), 4))]
    chosen = []
    used = set()
    for role in desired_roles:
        aid = pick_best_agent(role=role, task=goal, exclude=used, require_idle=False)
        if not aid:
            break
        used.add(aid)
        chosen.append({'agent': aid, 'role': role})
    return chosen


def router_summary() -> dict:
    """Telemetry snapshot of adaptive rankings, budget state, and active circuit-breakers."""
    b = _budget_snapshot()
    circuits = active_circuits()
    return {
        'circuits': circuits,
        'active_circuits': circuits,
        'budget_state': b.get('state', 'healthy'),
        'rankings': {
            role: rank_agents(role=role, require_idle=False)
            for role in ('general', 'architect', 'backend', 'frontend', 'qa', 'repair')
        },
    }
