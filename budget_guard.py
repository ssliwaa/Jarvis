"""Real-time cloud API budget guard, model downgrade policy, and cost ledger for Jarvis.

1. Tracks cumulative daily and monthly token/USD spend across Anthropic, OpenAI,
   Gemini, OpenRouter, and Groq calls.
2. Enforces a two-tier threshold:
   - `warning` (>= 80% daily/monthly limit): recommends `economy_cloud` and
     automatically downgrades auxiliary models (`claude-haiku-4-5`, `gemini-2.5-flash`).
   - `capped` (>= 100% daily/monthly limit): blocks background runs and raises
     `BudgetExceededError` on paid cloud calls unless `allow_override=True`.
3. Publishes live `budget.updated` SSE events on `event_bus`.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path

import agent_cli

DEFAULT_DAILY_USD = float(os.environ.get("JARVIS_DAILY_BUDGET_USD") or 5.0)
DEFAULT_MONTHLY_USD = float(os.environ.get("JARVIS_MONTHLY_BUDGET_USD") or 60.0)
DEFAULT_SOFT_RATIO = 0.80

MODEL_PRICING_PER_1M: dict[str, tuple[float, float]] = {
    "claude-opus": (15.0, 75.0),
    "claude-sonnet": (3.0, 15.0),
    "claude-haiku": (0.80, 4.0),
    "gpt-5": (5.0, 15.0),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.0),
    "gemini-2.5-pro": (1.25, 10.0),
    "gemini-2.5-flash": (0.15, 0.60),
    "gemini-2.0-flash": (0.10, 0.40),
    "groq": (0.05, 0.08),
}

ECONOMY_FALLBACKS: tuple[tuple[str, str], ...] = (
    ("claude-opus", "claude-haiku-4-5"),
    ("claude-sonnet", "claude-haiku-4-5"),
    ("gpt-5", "gpt-4o-mini"),
    ("gpt-4o", "gpt-4o-mini"),
    ("gemini-2.5-pro", "gemini-2.5-flash"),
)


class BudgetExceededError(Exception):
    """Raised when the cloud spend hits 100% of the daily or monthly hard cap."""


def _state_path() -> Path:
    return agent_cli.ROOT.parent / "budget_ledger.json"


@contextmanager
def _ledger_lock():
    base = agent_cli.ROOT.parent
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(base / ".budget.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _load_raw() -> dict:
    try:
        data = json.loads(_state_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_raw(data: dict) -> None:
    path = _state_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{os.urandom(4).hex()}-{time.time_ns()}")
    try:
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _today_keys() -> tuple[str, str]:
    now = time.localtime()
    return time.strftime("%Y-%m-%d", now), time.strftime("%Y-%m", now)


def estimate_cost_usd(model: str, input_tokens: int = 0, output_tokens: int = 0) -> float:
    """Estimate USD cost for `(model, input_tokens, output_tokens)`."""
    m = str(model or "").lower()
    in_rate, out_rate = (1.0, 4.0)
    for prefix, rates in MODEL_PRICING_PER_1M.items():
        if prefix in m:
            in_rate, out_rate = rates
            break
    cost = (max(0, int(input_tokens)) * in_rate + max(0, int(output_tokens)) * out_rate) / 1_000_000.0
    return round(cost, 6)


def _compute_status(raw: dict) -> dict:
    day_key, month_key = _today_keys()
    cfg = raw.get("config") if isinstance(raw.get("config"), dict) else {}
    daily_limit = max(0.05, float(cfg.get("daily_limit_usd") or DEFAULT_DAILY_USD))
    monthly_limit = max(0.10, float(cfg.get("monthly_limit_usd") or DEFAULT_MONTHLY_USD))
    soft_ratio = min(0.99, max(0.30, float(cfg.get("soft_ratio") or DEFAULT_SOFT_RATIO)))

    days = raw.get("days") if isinstance(raw.get("days"), dict) else {}
    months = raw.get("months") if isinstance(raw.get("months"), dict) else {}
    spent_today = round(float(days.get(day_key) or 0.0), 4)
    spent_month = round(float(months.get(month_key) or 0.0), 4)

    day_ratio = spent_today / daily_limit if daily_limit > 0 else 0.0
    month_ratio = spent_month / monthly_limit if monthly_limit > 0 else 0.0
    peak_ratio = max(day_ratio, month_ratio)

    if peak_ratio >= 1.0:
        state = "capped"
        tier = "local_only"
    elif peak_ratio >= soft_ratio:
        state = "warning"
        tier = "economy_cloud"
    else:
        state = "ok"
        tier = "primary_cloud"

    return {
        "ok": True,
        "day": day_key,
        "month": month_key,
        "spent_today_usd": spent_today,
        "daily_limit_usd": round(daily_limit, 2),
        "spent_month_usd": spent_month,
        "monthly_limit_usd": round(monthly_limit, 2),
        "soft_ratio": round(soft_ratio, 2),
        "utilization_ratio": round(peak_ratio, 4),
        "state": state,
        "recommended_cloud_tier": tier,
        "allow_background": state != "capped",
        "allow_paid_cloud": state != "capped",
        "prefer_economy_tier": state in ("warning", "capped"),
        "recent": list(raw.get("recent") or [])[-15:],
    }


def status() -> dict:
    """Return current budget snapshot (`ok` | `warning` | `capped`)."""
    with _ledger_lock():
        return _compute_status(_load_raw())


def allow_background_run() -> tuple[bool, str]:
    """Return `(allowed, reason)` for autonomous background jobs (`Night Shift`, auto-repair)."""
    snap = status()
    if snap["state"] == "capped":
        return (
            False,
            f"Osiągnięto dzienny/miesięczny limit budżetu chmurowego "
            f"(${snap['spent_today_usd']:.2f}/${snap['daily_limit_usd']:.2f}).",
        )
    return True, "ok"


def configure_limits(*, daily_limit_usd: float | None = None,
                     monthly_limit_usd: float | None = None,
                     soft_ratio: float | None = None) -> dict:
    """Update daily/monthly USD caps and soft-cap downgrade ratio."""
    with _ledger_lock():
        raw = _load_raw()
        cfg = dict(raw.get("config") or {})
        if daily_limit_usd is not None:
            cfg["daily_limit_usd"] = max(0.05, round(float(daily_limit_usd), 2))
        if monthly_limit_usd is not None:
            cfg["monthly_limit_usd"] = max(0.10, round(float(monthly_limit_usd), 2))
        if soft_ratio is not None:
            cfg["soft_ratio"] = min(0.99, max(0.30, round(float(soft_ratio), 2)))
        raw["config"] = cfg
        _save_raw(raw)
        snap = _compute_status(raw)

    try:
        import event_bus
        event_bus.publish("budget.updated", snap)
    except Exception:
        pass
    return snap


def record_spend(*, model: str = "unknown", input_tokens: int = 0,
                 output_tokens: int = 0, prompt_tokens: int = 0,
                 completion_tokens: int = 0, usd: float | None = None,
                 source: str = "api") -> dict:
    """Record a completed paid API call and return updated budget status."""
    in_tok = max(0, int(input_tokens or prompt_tokens or 0))
    out_tok = max(0, int(output_tokens or completion_tokens or 0))
    cost = round(float(usd), 6) if usd is not None else estimate_cost_usd(model, in_tok, out_tok)
    cost = max(0.0, cost)
    day_key, month_key = _today_keys()

    with _ledger_lock():
        raw = _load_raw()
        days = dict(raw.get("days") or {})
        months = dict(raw.get("months") or {})
        days[day_key] = round(float(days.get(day_key) or 0.0) + cost, 6)
        months[month_key] = round(float(months.get(month_key) or 0.0) + cost, 6)

        if len(days) > 45:
            for k in sorted(days.keys())[:-45]:
                days.pop(k, None)
        if len(months) > 18:
            for k in sorted(months.keys())[:-18]:
                months.pop(k, None)

        recent = list(raw.get("recent") or [])
        recent.append({
            "ts": round(time.time(), 3),
            "model": str(model or "unknown")[:64],
            "in_tok": in_tok,
            "out_tok": out_tok,
            "usd": cost,
            "source": str(source or "api")[:32],
        })
        raw["days"] = days
        raw["months"] = months
        raw["recent"] = recent[-60:]
        _save_raw(raw)
        snap = _compute_status(raw)

    try:
        import event_bus
        event_bus.publish("budget.updated", snap)
    except Exception:
        pass
    return snap


def enforce_and_select_model(requested_model: str = "", *, role: str = "general",
                             allow_override: bool = False) -> dict:
    """Enforce hard budget cap (100%) and auto-downgrade models at soft warning (>=80%)."""
    snap = status()
    state = snap["state"]
    req = str(requested_model or "").strip()

    if state in ("capped", "hard_cap") and not allow_override:
        raise BudgetExceededError(
            f"Osiągnięto 100% limitu budżetu chmurowego "
            f"(${snap['spent_today_usd']:.2f} / ${snap['daily_limit_usd']:.2f}). "
            f"Zwiększ limit w Mission Control lub użyj jawnego potwierdzenia."
        )

    selected = req
    downgraded = False
    if state in ("warning", "soft_cap", "capped", "hard_cap") and req and role != "architect_critical":
        lower = req.lower()
        for expensive_prefix, economy_model in ECONOMY_FALLBACKS:
            if expensive_prefix in lower and economy_model not in lower:
                selected = economy_model
                downgraded = True
                break

    return {
        "model": selected,
        "requested_model": req,
        "downgraded": downgraded,
        "budget_state": state,
        "utilization_ratio": snap["utilization_ratio"],
    }
