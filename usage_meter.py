"""Token accounting for every model call, process-wide.

The provider adapter records each real response here; the Operator keeps its own
per-job counters from the same normalized shape. Nothing is estimated: a call
without a usage block is not counted, so a fake client in tests never inflates
the numbers.
"""
from __future__ import annotations

import os
import threading
from datetime import datetime, timezone

LOCK = threading.Lock()
STARTED = datetime.now(timezone.utc).isoformat(timespec="seconds")
TOTAL = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
BY_MODEL: dict[str, dict] = {}
DAILY = {"day": datetime.now(timezone.utc).date().isoformat(), "calls": 0}


def reserve_call(limit_env: str = "JARVIS_DAILY_CALL_LIMIT") -> bool:
    """Count a paid request against an optional daily call budget.

    A zero/absent limit keeps the historical unlimited behaviour. Reservations
    count attempted requests, so a failing provider cannot be hammered for free.
    """
    try:
        limit = int(os.environ.get(limit_env, "0"))
    except ValueError:
        limit = 0
    if limit <= 0:
        return True
    today = datetime.now(timezone.utc).date().isoformat()
    with LOCK:
        if DAILY["day"] != today:
            DAILY["day"], DAILY["calls"] = today, 0
        if DAILY["calls"] >= limit:
            return False
        DAILY["calls"] += 1
    return True


def release_call() -> None:
    """Give back a reservation for a request that never called the model."""
    today = datetime.now(timezone.utc).date().isoformat()
    with LOCK:
        if DAILY["day"] == today and DAILY["calls"] > 0:
            DAILY["calls"] -= 1


def daily() -> dict:
    with LOCK:
        return dict(DAILY)


def _int(value) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def normalize(usage) -> dict:
    """Accept OpenAI (prompt/completion) and Anthropic (input/output) shapes."""
    if isinstance(usage, dict):
        data = usage
    else:
        data = getattr(usage, "__dict__", {}) or {}
    prompt = _int(data.get("prompt_tokens", data.get("input_tokens")))
    completion = _int(data.get("completion_tokens", data.get("output_tokens")))
    total = _int(data.get("total_tokens")) or prompt + completion
    return {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": total}


def price() -> tuple[float, float] | None:
    """Optional USD per 1M tokens, from the environment — never hard-coded."""
    try:
        prompt = float(os.environ.get("JARVIS_PRICE_INPUT", ""))
        completion = float(os.environ.get("JARVIS_PRICE_OUTPUT", ""))
    except (TypeError, ValueError):
        return None
    if prompt < 0 or completion < 0:
        return None
    return (prompt, completion)


def record(usage, model: str = "") -> dict:
    counts = normalize(usage)
    if not counts["total_tokens"]:
        counts["total_tokens"] = counts["prompt_tokens"] + counts["completion_tokens"]
    if not counts["total_tokens"]:
        return counts
    with LOCK:
        TOTAL["calls"] += 1
        for key, value in counts.items():
            TOTAL[key] += value
        row = BY_MODEL.setdefault(model or "unknown",
                                  {"calls": 0, "prompt_tokens": 0,
                                   "completion_tokens": 0, "total_tokens": 0})
        row["calls"] += 1
        for key, value in counts.items():
            row[key] += value
    return counts


def snapshot() -> dict:
    with LOCK:
        total = dict(TOTAL)
        by_model = {name: dict(row) for name, row in BY_MODEL.items()}
    rates = price()
    cost = None
    if rates:
        cost = round(total["prompt_tokens"] / 1_000_000 * rates[0]
                     + total["completion_tokens"] / 1_000_000 * rates[1], 6)
    return {"ok": True, "since": STARTED, **total, "daily": daily(),
            "cost_usd": cost, "priced": bool(rates),
            "pricing_note": "set JARVIS_PRICE_INPUT and JARVIS_PRICE_OUTPUT (USD per 1M tokens)"
                            if not rates else "",
            "by_model": by_model}


def reset() -> None:
    """Tests only: clear the counters."""
    global STARTED
    with LOCK:
        for key in TOTAL:
            TOTAL[key] = 0
        BY_MODEL.clear()
        STARTED = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
