"""Tunable operational limits for the REA teardown bay.

These are resource ceilings, not security switches. URL validation, the SSRF
guards, the one-teardown lock, approvals and the Chromium sandbox policy stay
unchanged. Values are read once at import; restart the service after changing
the environment.
"""
from __future__ import annotations

import os


def _number(name, default, minimum, maximum, cast=int):
    raw = os.environ.get(name)
    try:
        value = cast(str(raw).strip()) if raw is not None else default
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _bytes_from_mb(name, default_mb, minimum_mb, maximum_mb):
    return _number(name, default_mb, minimum_mb, maximum_mb) * 1024 * 1024


# --- REA command execution -------------------------------------------------
REA_TIMEOUT_DEFAULT = _number("JARVIS_REA_TIMEOUT", 1800, 10, 21600)
REA_TIMEOUT_MAX = max(REA_TIMEOUT_DEFAULT,
                      _number("JARVIS_REA_TIMEOUT_MAX", 21600, 60, 21600))
REA_STDOUT_BYTES = _bytes_from_mb("JARVIS_REA_STDOUT_MB", 128, 1, 512)
REA_STDERR_BYTES = _number("JARVIS_REA_STDERR_KB", 1024, 32, 16384) * 1024

# --- Ephemeral browser -----------------------------------------------------
BROWSER_ENDPOINT_TIMEOUT = _number("JARVIS_REA_ENDPOINT_TIMEOUT", 45.0, 5.0, 300.0, float)
BROWSER_LOAD_TIMEOUT = _number("JARVIS_REA_LOAD_TIMEOUT", 90.0, 5.0, 900.0, float)
BROWSER_TARGET_TIMEOUT = _number("JARVIS_REA_TARGET_TIMEOUT", 20.0, 2.0, 120.0, float)
BROWSER_INTRO_WAIT = _number("JARVIS_REA_INTRO_WAIT", 2.5, 0.0, 60.0, float)
BROWSER_SETTLE_SECONDS = _number("JARVIS_REA_SETTLE_SECONDS", 20.0, 1.0, 180.0, float)

# --- Evidence capture ------------------------------------------------------
INSPECT_MS = _number("JARVIS_REA_INSPECT_MS", 15000, 1000, 300000)
ANALYZE_MS = _number("JARVIS_REA_ANALYZE_MS", 5000, 500, 120000)
SCROLL_STEPS = _number("JARVIS_REA_SCROLL_STEPS", 32, 1, 1000)
WHEEL_DELTA = _number("JARVIS_REA_WHEEL_DELTA", 700, 100, 5000)
MAX_SOURCE_BYTES = _bytes_from_mb("JARVIS_REA_SOURCE_MB", 32, 1, 256)
MAX_FALLBACK_FETCHES = _number("JARVIS_REA_FALLBACK_FETCHES", 24, 1, 256)

# Timeouts for the REA commands the evidence lanes invoke. They scale with the
# observation window so raising JARVIS_REA_INSPECT_MS does not abort the lane.
REA_INSPECT_TIMEOUT = max(240, int(INSPECT_MS / 1000) + int(SCROLL_STEPS * 0.1) + 300)
REA_ANALYZE_TIMEOUT = max(300, int(ANALYZE_MS / 1000) + 300)
REA_SCREENSHOT_TIMEOUT = 180

# --- Teardown digest -------------------------------------------------------
DIGEST_CHARS = _number("JARVIS_REA_DIGEST_CHARS", 40000, 1000, 200000)
DIGEST_TOKENS = _number("JARVIS_REA_DIGEST_TOKENS", 12000, 1000, 65536)


def snapshot():
    """A small, non-secret view of the active ceilings for diagnostics."""
    return {
        "rea_timeout_seconds": REA_TIMEOUT_DEFAULT,
        "rea_timeout_max_seconds": REA_TIMEOUT_MAX,
        "stdout_mb": REA_STDOUT_BYTES // (1024 * 1024),
        "stderr_kb": REA_STDERR_BYTES // 1024,
        "endpoint_timeout_seconds": BROWSER_ENDPOINT_TIMEOUT,
        "load_timeout_seconds": BROWSER_LOAD_TIMEOUT,
        "target_timeout_seconds": BROWSER_TARGET_TIMEOUT,
        "intro_wait_seconds": BROWSER_INTRO_WAIT,
        "settle_seconds": BROWSER_SETTLE_SECONDS,
        "inspect_ms": INSPECT_MS,
        "analyze_ms": ANALYZE_MS,
        "scroll_steps": SCROLL_STEPS,
        "wheel_delta": WHEEL_DELTA,
        "source_mb": MAX_SOURCE_BYTES // (1024 * 1024),
        "fallback_fetches": MAX_FALLBACK_FETCHES,
        "digest_chars": DIGEST_CHARS,
        "digest_tokens": DIGEST_TOKENS,
    }
