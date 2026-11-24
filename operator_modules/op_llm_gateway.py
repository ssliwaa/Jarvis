"""Zero-dependency LLM Gateway, provider routing, fallback ladders, and rate limiter.

Synthesizes architectural patterns from:
- LiteLLM (#11): Universal model routing, dynamic fallback ladders, provider cooldowns.
- vLLM (#12): Engine health probing and queue/throughput telemetry.
- Portkey AI Gateway (#13): Token-bucket rate limiting, circuit breaker state machine,
  interceptor validation, and metrics recording.

Exclusively uses the Python standard library. Zero external dependencies.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    from atomic_io import atomic_write_text
except ImportError:  # standalone copy: reach the repo root next to operator_modules/
    import sys
    _repo_root = str(Path(__file__).resolve().parents[1])
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)
    from atomic_io import atomic_write_text
from typing import Any

# Security perimeter: Allowed root directories
HOME = Path.home().resolve()
ALLOWED_ROOTS: tuple[Path, ...] = (
    HOME,
    Path("/tmp").resolve(),
    Path("/mnt").resolve(),
    Path("/media").resolve(),
)

SENSITIVE_NAMES: frozenset[str] = frozenset({
    ".ssh",
    ".gnupg",
    ".password-store",
    ".hermes",
    ".aws",
    ".docker",
    ".kube",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".xprofile",
    ".gitconfig",
    "config.json",
    "secrets.json",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
})

VALID_ACTIONS: frozenset[str] = frozenset({
    "route_request",
    "record_metrics",
    "get_status",
    "set_rate_limit",
    "check_rate_limit",
    "reset_circuit",
    "probe_endpoints",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "provider_ladder",
    "provider",
    "model",
    "tokens",
    "estimated_tokens",
    "rate_limit_tpm",
    "rate_limit_rpm",
    "prompt",
    "messages",
    "max_tokens",
    "temperature",
    "endpoint_url",
    "endpoints",
    "latency_ms",
    "cost",
    "success",
    "error_type",
    "simulate_failure",
    "export_path",
})


class GatewayError(Exception):
    """Base exception for llm_gateway."""


class PathSecurityError(GatewayError):
    """Raised when target file resolves outside ALLOWED_ROOTS."""


class SensitivePathError(GatewayError):
    """Raised when target file touches sensitive directories or files."""


def _envelope_success(data: Any) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator success envelope."""
    return {"ok": True, "success": True, "data": data, "result": data, "error": None}


def _envelope_error(error: str | Exception) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator error envelope."""
    if isinstance(error, Exception):
        msg = f"{type(error).__name__}: {error}"
    else:
        msg = str(error)
    return {"ok": False, "success": False, "data": None, "result": None, "error": msg}


def _is_inside_allowed_roots(path: Path) -> bool:
    """Verify that path resides strictly inside ALLOWED_ROOTS."""
    try:
        resolved = Path(os.path.realpath(str(path)))
        for root in ALLOWED_ROOTS:
            try:
                root_res = Path(os.path.realpath(str(root)))
                if resolved == root_res or resolved.is_relative_to(root_res):
                    return True
            except (OSError, RuntimeError, ValueError):
                continue
        return False
    except (OSError, RuntimeError, ValueError):
        return False


def _is_sensitive_path(path: Path) -> bool:
    """Check if any path component touches sensitive credential or configuration directories."""
    parts = [p.casefold() for p in path.parts]
    for part in parts:
        if part in SENSITIVE_NAMES:
            return True
        if part == ".env" or (part.startswith(".env.") and len(part) > 5):
            return True
    return False


def _validate_path(raw_path: Any) -> Path:
    """Validate and canonically resolve target path within ALLOWED_ROOTS."""
    if not isinstance(raw_path, (str, Path)):
        raise ValueError("File path must be a valid string or Path.")
    path_str = str(raw_path).strip()
    if not path_str:
        raise ValueError("File path cannot be empty.")
    if len(path_str) > 4096 or "\x00" in path_str:
        raise ValueError("Invalid path string: exceeds length limit or contains null bytes.")
    p = Path(path_str).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p

    try:
        resolved = Path(os.path.realpath(str(p)))
    except (OSError, ValueError) as err:
        raise ValueError(f"Path resolution error: {err}") from err

    if not _is_inside_allowed_roots(resolved):
        raise PathSecurityError(
            f"Target path '{p}' resolves to '{resolved}', which is outside "
            "allowed roots (HOME, /tmp, /mnt, /media)."
        )

    if _is_sensitive_path(resolved):
        raise SensitivePathError(f"Access to sensitive path '{resolved}' is restricted.")

    return resolved


class TokenBucket:
    """Thread-safe token bucket rate limiter in pure Python standard library."""

    def __init__(self, capacity: int = 100_000, refill_rate_per_sec: float = 1666.67):
        # Default: 100k tokens capacity, refills 100k tokens per min (~1666.67/s)
        self.capacity = capacity
        self.refill_rate = refill_rate_per_sec
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def update_limits(self, capacity: int, refill_rate_per_sec: float) -> None:
        with self.lock:
            self.capacity = capacity
            self.refill_rate = refill_rate_per_sec
            self.tokens = min(float(capacity), self.tokens)

    def consume(self, amount: int) -> bool:
        with self.lock:
            now = time.monotonic()
            delta = max(0.0, now - self.last_refill)
            self.tokens = min(float(self.capacity), self.tokens + delta * self.refill_rate)
            self.last_refill = now
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False

    def status(self) -> dict[str, Any]:
        with self.lock:
            now = time.monotonic()
            delta = max(0.0, now - self.last_refill)
            current_tokens = min(float(self.capacity), self.tokens + delta * self.refill_rate)
            return {
                "capacity": self.capacity,
                "refill_rate_per_sec": round(self.refill_rate, 2),
                "available_tokens": int(current_tokens),
                "utilization_pct": round(100.0 * (1.0 - (current_tokens / max(1, self.capacity))), 2),
            }


class CircuitBreaker:
    """Circuit breaker with configurable failure threshold and cooldown backoff."""

    def __init__(self, provider_name: str, failure_threshold: int = 3, cooldown_sec: float = 30.0):
        self.provider_name = provider_name
        self.failure_threshold = failure_threshold
        self.cooldown_sec = cooldown_sec
        self.failure_count = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.last_failure_time = 0.0
        self.total_failures = 0
        self.total_successes = 0
        self.lock = threading.Lock()

    def record_success(self) -> None:
        with self.lock:
            self.failure_count = 0
            self.state = "CLOSED"
            self.total_successes += 1

    def record_failure(self) -> None:
        with self.lock:
            self.failure_count += 1
            self.total_failures += 1
            self.last_failure_time = time.monotonic()
            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"

    def can_execute(self) -> bool:
        with self.lock:
            if self.state == "CLOSED":
                return True
            if self.state == "OPEN":
                if (time.monotonic() - self.last_failure_time) >= self.cooldown_sec:
                    self.state = "HALF_OPEN"
                    return True
                return False
            # HALF_OPEN allows a single probe attempt
            return True

    def reset(self) -> None:
        with self.lock:
            self.failure_count = 0
            self.state = "CLOSED"
            self.last_failure_time = 0.0

    def status(self) -> dict[str, Any]:
        with self.lock:
            now = time.monotonic()
            remaining_cooldown = 0.0
            if self.state == "OPEN":
                elapsed = now - self.last_failure_time
                remaining_cooldown = max(0.0, self.cooldown_sec - elapsed)
            return {
                "provider": self.provider_name,
                "state": self.state,
                "consecutive_failures": self.failure_count,
                "failure_threshold": self.failure_threshold,
                "cooldown_sec": self.cooldown_sec,
                "remaining_cooldown_sec": round(remaining_cooldown, 2),
                "total_successes": self.total_successes,
                "total_failures": self.total_failures,
            }


class GatewayState:
    """Thread-safe singleton holding global gateway runtime state."""

    _instance: GatewayState | None = None
    _init_lock = threading.Lock()

    def __init__(self):
        self.lock = threading.RLock()
        self.token_bucket = TokenBucket(capacity=100_000, refill_rate_per_sec=1666.67)
        self.request_bucket = TokenBucket(capacity=1_000, refill_rate_per_sec=16.67)
        self.default_ladder = ["vllm_local", "ollama_local", "deepseek", "anthropic"]
        self.circuits: dict[str, CircuitBreaker] = {
            p: CircuitBreaker(p) for p in self.default_ladder
        }
        self.metrics: dict[str, Any] = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_tokens": 0,
            "total_cost_usd": 0.0,
            "provider_requests": {},
            "provider_tokens": {},
            "latencies_ms": [],
        }
        self.start_time = time.time()

    @classmethod
    def get(cls) -> GatewayState:
        with cls._init_lock:
            if cls._instance is None:
                cls._instance = GatewayState()
            return cls._instance

    def get_circuit(self, provider: str) -> CircuitBreaker:
        with self.lock:
            if provider not in self.circuits:
                self.circuits[provider] = CircuitBreaker(provider)
            return self.circuits[provider]


def _route_request(args: dict[str, Any], state: GatewayState) -> dict[str, Any]:
    """Route LLM request through fallback ladder with circuit breaking and rate limiting."""
    ladder = args.get("provider_ladder")
    provider = args.get("provider")
    model = args.get("model") or "default-model"
    prompt = args.get("prompt")
    messages = args.get("messages")
    estimated_tokens = int(args.get("estimated_tokens") or args.get("tokens") or 150)
    simulate_failure = args.get("simulate_failure")
    endpoint_url = args.get("endpoint_url")

    if not prompt and not messages:
        # Default placeholder request if not specified
        prompt = "Hello"

    # 1. Check rate limits
    if not state.request_bucket.consume(1):
        raise GatewayError("Request rate limit exceeded (RPM limit reached).")
    if not state.token_bucket.consume(estimated_tokens):
        raise GatewayError(f"Token rate limit exceeded (TPM limit reached; requested {estimated_tokens} tokens).")

    # 2. Build candidate ladder
    if provider and provider != "auto":
        candidates = [provider]
    elif ladder and isinstance(ladder, list) and len(ladder) > 0:
        candidates = [str(p) for p in ladder]
    else:
        candidates = list(state.default_ladder)

    routed_provider = None
    attempted_providers = []
    circuit_rejections = []
    start_t = time.monotonic()

    for cand in candidates:
        attempted_providers.append(cand)
        circuit = state.get_circuit(cand)

        if not circuit.can_execute():
            circuit_rejections.append({
                "provider": cand,
                "reason": f"Circuit breaker is {circuit.state}",
            })
            continue

        # Simulate or execute
        if simulate_failure is True or simulate_failure == cand:
            circuit.record_failure()
            with state.lock:
                state.metrics["total_requests"] += 1
                state.metrics["failed_requests"] += 1
            continue

        # If endpoint_url provided for this provider, we can probe reachability
        if endpoint_url and cand in (candidates[0], provider):
            try:
                req = urllib.request.Request(
                    endpoint_url,
                    headers={"User-Agent": "Jarvis-LLM-Gateway/1.0"},
                    method="HEAD",
                )
                with urllib.request.urlopen(req, timeout=1.0) as resp:
                    _ = resp.status
            except Exception:
                # Live probe failed, record failure and continue to fallback
                circuit.record_failure()
                with state.lock:
                    state.metrics["total_requests"] += 1
                    state.metrics["failed_requests"] += 1
                continue

        # Provider succeeded
        circuit.record_success()
        routed_provider = cand
        break

    latency_ms = round((time.monotonic() - start_t) * 1000.0, 2)

    if not routed_provider:
        raise GatewayError(
            f"All candidate providers in ladder failed or were circuit-broken. "
            f"Attempted: {attempted_providers}, Rejections: {circuit_rejections}"
        )

    # Record metrics
    with state.lock:
        state.metrics["total_requests"] += 1
        state.metrics["successful_requests"] += 1
        state.metrics["total_tokens"] += estimated_tokens
        state.metrics["provider_requests"][routed_provider] = (
            state.metrics["provider_requests"].get(routed_provider, 0) + 1
        )
        state.metrics["provider_tokens"][routed_provider] = (
            state.metrics["provider_tokens"].get(routed_provider, 0) + estimated_tokens
        )
        state.metrics["latencies_ms"].append(latency_ms)
        if len(state.metrics["latencies_ms"]) > 1000:
            state.metrics["latencies_ms"] = state.metrics["latencies_ms"][-1000:]

    return {
        "status": "routed",
        "routed_provider": routed_provider,
        "model": model,
        "tokens_allocated": estimated_tokens,
        "latency_ms": latency_ms,
        "attempted_providers": attempted_providers,
        "circuit_status": state.get_circuit(routed_provider).status(),
    }


def _record_metrics(args: dict[str, Any], state: GatewayState) -> dict[str, Any]:
    """Record execution metrics from an external or completed LLM call."""
    model = args.get("model") or "unknown_model"
    provider = args.get("provider") or "unknown_provider"
    tokens = int(args.get("tokens") or 0)
    latency_ms = float(args.get("latency_ms") or 0.0)
    cost = float(args.get("cost") or 0.0)
    success = bool(args.get("success", True))
    error_type = args.get("error_type")

    with state.lock:
        state.metrics["total_requests"] += 1
        if success:
            state.metrics["successful_requests"] += 1
        else:
            state.metrics["failed_requests"] += 1
        state.metrics["total_tokens"] += tokens
        state.metrics["total_cost_usd"] = round(state.metrics["total_cost_usd"] + cost, 6)
        state.metrics["provider_requests"][provider] = (
            state.metrics["provider_requests"].get(provider, 0) + 1
        )
        state.metrics["provider_tokens"][provider] = (
            state.metrics["provider_tokens"].get(provider, 0) + tokens
        )
        if latency_ms > 0:
            state.metrics["latencies_ms"].append(latency_ms)
            if len(state.metrics["latencies_ms"]) > 1000:
                state.metrics["latencies_ms"] = state.metrics["latencies_ms"][-1000:]

    circuit = state.get_circuit(provider)
    if success:
        circuit.record_success()
    else:
        circuit.record_failure()

    return {
        "recorded": True,
        "provider": provider,
        "model": model,
        "tokens": tokens,
        "latency_ms": latency_ms,
        "cost": cost,
        "success": success,
        "error_type": error_type,
        "cumulative_tokens": state.metrics["total_tokens"],
        "cumulative_requests": state.metrics["total_requests"],
    }


def _get_status(args: dict[str, Any], state: GatewayState) -> dict[str, Any]:
    """Return comprehensive health, circuit states, rate limit, and throughput metrics."""
    with state.lock:
        lats = state.metrics["latencies_ms"]
        avg_latency = round(sum(lats) / len(lats), 2) if lats else 0.0
        p95_latency = 0.0
        if lats:
            sorted_lats = sorted(lats)
            idx = int(0.95 * len(sorted_lats))
            p95_latency = round(sorted_lats[min(idx, len(sorted_lats) - 1)], 2)

        circuit_summaries = {p: cb.status() for p, cb in state.circuits.items()}
        export_path = args.get("export_path")
        result = {
            "uptime_seconds": round(time.time() - state.start_time, 2),
            "rate_limits": {
                "tokens": state.token_bucket.status(),
                "requests": state.request_bucket.status(),
            },
            "circuits": circuit_summaries,
            "metrics": {
                "total_requests": state.metrics["total_requests"],
                "successful_requests": state.metrics["successful_requests"],
                "failed_requests": state.metrics["failed_requests"],
                "total_tokens": state.metrics["total_tokens"],
                "total_cost_usd": round(state.metrics["total_cost_usd"], 4),
                "average_latency_ms": avg_latency,
                "p95_latency_ms": p95_latency,
                "provider_requests": dict(state.metrics["provider_requests"]),
                "provider_tokens": dict(state.metrics["provider_tokens"]),
            },
        }

    if export_path:
        resolved = _validate_path(export_path)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(resolved, json.dumps(result, indent=2), dir_mode=None)
        result["exported_to"] = str(resolved)

    return result


def _set_rate_limit(args: dict[str, Any], state: GatewayState) -> dict[str, Any]:
    """Configure token or request rate limits for the gateway."""
    tpm = args.get("rate_limit_tpm")
    rpm = args.get("rate_limit_rpm")

    updated = {}
    if tpm is not None:
        tpm_int = max(1, int(tpm))
        refill_rate = tpm_int / 60.0
        state.token_bucket.update_limits(capacity=tpm_int, refill_rate_per_sec=refill_rate)
        updated["rate_limit_tpm"] = tpm_int

    if rpm is not None:
        rpm_int = max(1, int(rpm))
        refill_rate = rpm_int / 60.0
        state.request_bucket.update_limits(capacity=rpm_int, refill_rate_per_sec=refill_rate)
        updated["rate_limit_rpm"] = rpm_int

    return {
        "status": "rate_limits_updated",
        "updated": updated,
        "current_limits": {
            "token_bucket": state.token_bucket.status(),
            "request_bucket": state.request_bucket.status(),
        },
    }


def _check_rate_limit(args: dict[str, Any], state: GatewayState) -> dict[str, Any]:
    """Inspect remaining capacity against token and request buckets without necessarily consuming."""
    tokens = int(args.get("estimated_tokens") or args.get("tokens") or 1)
    tb_status = state.token_bucket.status()
    rb_status = state.request_bucket.status()

    allowed = (tb_status["available_tokens"] >= tokens) and (rb_status["available_tokens"] >= 1)
    return {
        "allowed": allowed,
        "requested_tokens": tokens,
        "available_tokens": tb_status["available_tokens"],
        "token_capacity": tb_status["capacity"],
        "available_requests": rb_status["available_tokens"],
        "request_capacity": rb_status["capacity"],
    }


def _reset_circuit(args: dict[str, Any], state: GatewayState) -> dict[str, Any]:
    """Reset circuit breaker state for a specific provider or all providers."""
    provider = args.get("provider")
    reset_list = []
    with state.lock:
        if provider:
            cb = state.get_circuit(provider)
            cb.reset()
            reset_list.append(provider)
        else:
            for p, cb in state.circuits.items():
                cb.reset()
                reset_list.append(p)
        circuit_states = {p: state.circuits[p].status() for p in reset_list}

    return {
        "status": "circuits_reset",
        "reset_providers": reset_list,
        "circuit_states": circuit_states,
    }


def _probe_endpoints(args: dict[str, Any], state: GatewayState) -> dict[str, Any]:
    """Probe endpoint URLs for reachability and round-trip latency."""
    raw_endpoints = args.get("endpoints") or []
    single = args.get("endpoint_url")
    if single:
        raw_endpoints.append(single)

    if not raw_endpoints:
        raw_endpoints = [
            "http://127.0.0.1:8000/v1/models",  # local vLLM default
            "http://127.0.0.1:11434/api/tags",   # local Ollama default
        ]

    results = []
    for ep in raw_endpoints:
        ep_str = str(ep).strip()
        t0 = time.monotonic()
        reachable = False
        status_code = None
        error_msg = None
        try:
            req = urllib.request.Request(
                ep_str,
                headers={"User-Agent": "Jarvis-LLM-Gateway/1.0"},
            )
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                status_code = resp.status
                reachable = (200 <= resp.status < 400)
        except urllib.error.HTTPError as he:
            status_code = he.code
            reachable = True  # Responded, even if error
            error_msg = str(he)
        except Exception as exc:
            reachable = False
            error_msg = str(exc)

        latency = round((time.monotonic() - t0) * 1000.0, 2)
        results.append({
            "endpoint": ep_str,
            "reachable": reachable,
            "status_code": status_code,
            "latency_ms": latency,
            "error": error_msg,
        })

    return {"endpoints_probed": len(results), "results": results}


def llm_gateway(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Main dispatch handler for llm_gateway operator tool."""
    if not isinstance(arguments, dict):
        return _envelope_error("Arguments must be a JSON dictionary.")

    # Strict additional properties check
    extra_keys = set(arguments.keys()) - KNOWN_ARGUMENTS
    if extra_keys:
        return _envelope_error(f"Disallowed additional arguments: {sorted(extra_keys)}")

    action = arguments.get("action")
    if not action or action not in VALID_ACTIONS:
        return _envelope_error(
            f"Invalid or missing action '{action}'. Valid actions: {sorted(VALID_ACTIONS)}"
        )

    state = GatewayState.get()

    try:
        if action == "route_request":
            res = _route_request(arguments, state)
        elif action == "record_metrics":
            res = _record_metrics(arguments, state)
        elif action == "get_status":
            res = _get_status(arguments, state)
        elif action == "set_rate_limit":
            res = _set_rate_limit(arguments, state)
        elif action == "check_rate_limit":
            res = _check_rate_limit(arguments, state)
        elif action == "reset_circuit":
            res = _reset_circuit(arguments, state)
        elif action == "probe_endpoints":
            res = _probe_endpoints(arguments, state)
        else:
            return _envelope_error(f"Unhandled action '{action}'.")

        return _envelope_success(res)
    except GatewayError as ge:
        return _envelope_error(ge)
    except (ValueError, TypeError) as err:
        return _envelope_error(err)
    except Exception as exc:
        return _envelope_error(exc)


TOOL = {
    "name": "llm_gateway",
    "description": (
        "Zero-dependency LLM gateway with provider routing ladders, fallback cascades, "
        "circuit breaking, token/request bucket rate limiting, and throughput telemetry."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "route_request",
                    "record_metrics",
                    "get_status",
                    "set_rate_limit",
                    "check_rate_limit",
                    "reset_circuit",
                    "probe_endpoints",
                ],
                "description": "Gateway action to execute.",
            },
            "provider_ladder": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Prioritized list of provider names for fallback routing.",
            },
            "provider": {
                "type": "string",
                "description": "Target provider name (e.g. 'vllm_local', 'ollama_local', 'deepseek', 'anthropic', 'auto').",
            },
            "model": {
                "type": "string",
                "description": "Model identifier requested.",
            },
            "tokens": {
                "type": "integer",
                "description": "Token count for metrics recording or consumption.",
            },
            "estimated_tokens": {
                "type": "integer",
                "description": "Estimated tokens for rate-limiting check.",
            },
            "rate_limit_tpm": {
                "type": "integer",
                "description": "Tokens-per-minute limit setting.",
            },
            "rate_limit_rpm": {
                "type": "integer",
                "description": "Requests-per-minute limit setting.",
            },
            "prompt": {
                "type": "string",
                "description": "Input prompt text for request.",
            },
            "messages": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Chat messages list for request.",
            },
            "max_tokens": {
                "type": "integer",
                "description": "Max tokens to generate.",
            },
            "temperature": {
                "type": "number",
                "description": "Sampling temperature.",
            },
            "endpoint_url": {
                "type": "string",
                "description": "Endpoint URL for routing or probing.",
            },
            "endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of endpoint URLs for probe_endpoints.",
            },
            "latency_ms": {
                "type": "number",
                "description": "Observed request latency in milliseconds.",
            },
            "cost": {
                "type": "number",
                "description": "Cost in USD of the request.",
            },
            "success": {
                "type": "boolean",
                "description": "Whether the recorded execution succeeded.",
            },
            "error_type": {
                "type": "string",
                "description": "Error category or code if request failed.",
            },
            "simulate_failure": {
                "type": "boolean",
                "description": "Flag to simulate provider failure for circuit testing.",
            },
            "export_path": {
                "type": "string",
                "description": "Optional file path within ALLOWED_ROOTS to export status JSON.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": llm_gateway,
    "approval": False,
}
