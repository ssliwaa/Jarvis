"""Zero-dependency local LLM discovery, health probing, and telemetry operator module.

Inspired by Ollama, llama.cpp, LocalAI, and LLM CLI: monitors loopback REST APIs,
discovers installed and active models, queries VRAM/slot metrics, tests TCP/HTTP latency,
and evaluates offline AI execution readiness. Exclusively uses Python standard library.
"""

from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Optional

DEFAULT_HOST = "127.0.0.1"
DEFAULT_TIMEOUT = 2.0  # seconds

# Standard local inference service ports
DEFAULT_PORTS: dict[str, int] = {
    "ollama": 11434,
    "llama_server": 8080,
    "localai": 8080,
    "vllm": 8000,
}

ALLOWED_HOSTS: frozenset[str] = frozenset({
    "127.0.0.1",
    "localhost",
    "::1",
    "0.0.0.0",
})

VALID_ACTIONS: frozenset[str] = frozenset({
    "probe_endpoints",
    "get_model_info",
    "check_readiness",
    "probe_all",
    "probe_ollama",
    "probe_llama_server",
    "probe_localai",
    "benchmark_ping",
})


class LocalLLMProbeError(Exception):
    """Base exception for local_llm_probe operations."""


class NetworkSecurityError(LocalLLMProbeError):
    """Raised when request attempts to reach non-loopback or disallowed addresses."""


def _envelope_success(data: Any) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator success envelope."""
    return {"ok": True, "success": True, "data": data, "result": data, "error": None}


def _envelope_error(err: str | Exception) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator error envelope."""
    msg = f"{type(err).__name__}: {err}" if isinstance(err, Exception) else str(err)
    return {"ok": False, "success": False, "data": None, "result": None, "error": msg}


def _validate_host(host: str) -> str:
    """Ensure target host is strictly constrained to loopback interfaces."""
    clean_host = str(host).strip().lower()
    if clean_host not in ALLOWED_HOSTS and not clean_host.startswith("127."):
        raise NetworkSecurityError(
            f"Host '{host}' is not permitted. Probes are strictly restricted to local loopback (127.0.0.1, localhost)."
        )
    return clean_host


def _http_get_json(url: str, timeout: float) -> tuple[Optional[dict[str, Any]], Optional[int], float, Optional[str]]:
    """Perform a lightweight HTTP GET request, returning parsed JSON, status code, latency ms, and error."""
    start = time.perf_counter()
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Jarvis-LocalLLM-Probe/1.0", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            status = resp.status
            raw_data = resp.read(256 * 1024)  # cap at 256 KB
            try:
                parsed = json.loads(raw_data.decode("utf-8", errors="replace"))
                return parsed, status, elapsed_ms, None
            except json.JSONDecodeError:
                return None, status, elapsed_ms, "Non-JSON response received"
    except urllib.error.HTTPError as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return None, exc.code, elapsed_ms, f"HTTP Error {exc.code}: {exc.reason}"
    except (urllib.error.URLError, socket.timeout, ConnectionRefusedError, OSError) as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return None, None, elapsed_ms, str(exc)


def _tcp_ping(host: str, port: int, timeout: float) -> tuple[bool, float, Optional[str]]:
    """Test TCP socket connection latency to host and port."""
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return True, elapsed_ms, None
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return False, elapsed_ms, str(exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _action_probe_ollama(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Probe Ollama instance on host:port for version, installed models, and active processes."""
    base_url = f"http://{host}:{port}"

    # 1. Probe /api/tags for installed models
    tags_data, status, latency_ms, error = _http_get_json(f"{base_url}/api/tags", timeout)
    if error or not tags_data:
        return {
            "engine": "ollama",
            "host": host,
            "port": port,
            "reachable": False,
            "status_code": status,
            "latency_ms": round(latency_ms, 2),
            "error": error or "Failed to connect to Ollama service",
            "models_count": 0,
            "models": [],
            "running_models": [],
        }

    models_raw = tags_data.get("models", [])
    models_summary = []
    for m in models_raw:
        details = m.get("details", {})
        models_summary.append({
            "name": m.get("name"),
            "size_bytes": m.get("size", 0),
            "format": details.get("format", "gguf"),
            "family": details.get("family"),
            "parameter_size": details.get("parameter_size"),
            "quantization_level": details.get("quantization_level"),
            "modified_at": m.get("modified_at"),
        })

    # 2. Probe /api/ps for currently running models in VRAM
    ps_data, _, _, _ = _http_get_json(f"{base_url}/api/ps", timeout)
    running_models = []
    if ps_data and "models" in ps_data:
        for rm in ps_data["models"]:
            running_models.append({
                "name": rm.get("name"),
                "size_vram_bytes": rm.get("size_vram", 0),
                "expires_at": rm.get("expires_at"),
            })

    # 3. Probe /api/version
    version_data, _, _, _ = _http_get_json(f"{base_url}/api/version", timeout)
    version = version_data.get("version", "unknown") if version_data else "unknown"

    return {
        "engine": "ollama",
        "version": version,
        "host": host,
        "port": port,
        "reachable": True,
        "status_code": status,
        "latency_ms": round(latency_ms, 2),
        "models_count": len(models_summary),
        "models": models_summary,
        "running_models_count": len(running_models),
        "running_models": running_models,
        "vram_in_use_bytes": sum(rm.get("size_vram_bytes", 0) for rm in running_models),
    }


def _action_probe_llama_server(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Probe llama.cpp / llama-server instance for health, slots, and props."""
    base_url = f"http://{host}:{port}"

    # Probe /health
    health_data, status, latency_ms, error = _http_get_json(f"{base_url}/health", timeout)
    if error and status != 200:
        return {
            "engine": "llama_server",
            "host": host,
            "port": port,
            "reachable": False,
            "status_code": status,
            "latency_ms": round(latency_ms, 2),
            "error": error or "llama-server is not responding",
        }

    # Probe /props
    props_data, _, _, _ = _http_get_json(f"{base_url}/props", timeout)
    default_gen = props_data.get("default_generation_settings", {}) if props_data else {}

    # Probe /slots
    slots_data, _, _, _ = _http_get_json(f"{base_url}/slots", timeout)
    active_slots = 0
    total_slots = 0
    if isinstance(slots_data, list):
        total_slots = len(slots_data)
        active_slots = sum(1 for s in slots_data if s.get("state", 0) != 0)

    return {
        "engine": "llama_server",
        "host": host,
        "port": port,
        "reachable": True,
        "status_code": status or 200,
        "latency_ms": round(latency_ms, 2),
        "server_status": health_data.get("status", "ok") if health_data else "ok",
        "total_slots": total_slots,
        "active_slots": active_slots,
        "n_ctx": default_gen.get("n_ctx"),
        "model_path": props_data.get("model_path", "loaded") if props_data else "loaded",
    }


def _action_probe_localai(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Probe LocalAI instance for model endpoints and readiness."""
    base_url = f"http://{host}:{port}"
    models_data, status, latency_ms, error = _http_get_json(f"{base_url}/v1/models", timeout)

    if error or not models_data:
        return {
            "engine": "localai",
            "host": host,
            "port": port,
            "reachable": False,
            "status_code": status,
            "latency_ms": round(latency_ms, 2),
            "error": error or "LocalAI is not responding",
            "models": [],
        }

    models_list = []
    for item in models_data.get("data", []):
        models_list.append(item.get("id"))

    return {
        "engine": "localai",
        "host": host,
        "port": port,
        "reachable": True,
        "status_code": status,
        "latency_ms": round(latency_ms, 2),
        "models_count": len(models_list),
        "models": models_list,
    }


def _action_probe_endpoints(endpoints: list[str], timeout: float) -> dict[str, Any]:
    """Probe arbitrary list of HTTP endpoints on loopback."""
    results: list[dict[str, Any]] = []

    for ep in endpoints:
        m = re.match(r"^https?://([^:/]+)(?::(\d+))?", ep.strip())
        if not m:
            results.append({
                "endpoint": ep,
                "reachable": False,
                "error": "Malformed endpoint URL",
            })
            continue

        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else 80
        try:
            _validate_host(host)
        except NetworkSecurityError as sec_err:
            results.append({
                "endpoint": ep,
                "reachable": False,
                "error": str(sec_err),
            })
            continue

        data, status, latency_ms, error = _http_get_json(ep, timeout)
        detected_engine = "unknown"
        if data and isinstance(data, dict):
            if "models" in data and ("api/tags" in ep or "ollama" in str(data)):
                detected_engine = "ollama"
            elif "default_generation_settings" in data or "slots" in ep:
                detected_engine = "llama_server"
            elif "data" in data and isinstance(data.get("data"), list):
                detected_engine = "openai_compatible"

        results.append({
            "endpoint": ep,
            "host": host,
            "port": port,
            "reachable": error is None or (status is not None and status < 500),
            "status_code": status,
            "latency_ms": round(latency_ms, 2),
            "detected_engine": detected_engine,
            "error": error,
        })

    return {
        "probed_count": len(results),
        "reachable_count": sum(1 for r in results if r["reachable"]),
        "endpoints": results,
    }


def _action_probe_all(host: str, timeout: float) -> dict[str, Any]:
    """Concurrently or sequentially probe all standard local LLM services."""
    _validate_host(host)
    ollama_res = _action_probe_ollama(host, DEFAULT_PORTS["ollama"], timeout)
    llama_res = _action_probe_llama_server(host, DEFAULT_PORTS["llama_server"], timeout)
    vllm_res, vllm_status, vllm_lat, _ = _http_get_json(f"http://{host}:{DEFAULT_PORTS['vllm']}/v1/models", timeout)

    return {
        "host": host,
        "ollama": ollama_res,
        "llama_server": llama_res,
        "vllm": {
            "reachable": vllm_status == 200,
            "latency_ms": round(vllm_lat, 2),
            "models_count": len(vllm_res.get("data", [])) if vllm_res else 0,
        },
        "any_service_available": ollama_res["reachable"] or llama_res["reachable"] or (vllm_status == 200),
    }


def _action_check_readiness(host: str, timeout: float) -> dict[str, Any]:
    """Evaluate readiness of local inference tier for offline fallback."""
    all_probes = _action_probe_all(host, timeout)
    available_engines: list[str] = []
    total_models = 0
    best_latency = float("inf")
    recommended_model = None

    if all_probes["ollama"]["reachable"]:
        available_engines.append("ollama")
        total_models += all_probes["ollama"]["models_count"]
        best_latency = min(best_latency, all_probes["ollama"]["latency_ms"])
        if all_probes["ollama"]["models"]:
            recommended_model = all_probes["ollama"]["models"][0]["name"]

    if all_probes["llama_server"]["reachable"]:
        available_engines.append("llama_server")
        best_latency = min(best_latency, all_probes["llama_server"]["latency_ms"])
        if not recommended_model:
            recommended_model = all_probes["llama_server"].get("model_path")

    if all_probes["vllm"]["reachable"]:
        available_engines.append("vllm")
        best_latency = min(best_latency, all_probes["vllm"]["latency_ms"])

    is_ready = len(available_engines) > 0

    return {
        "is_ready": is_ready,
        "mode": "local_inference_ready" if is_ready else "cloud_only_no_local_daemons",
        "available_engines": available_engines,
        "total_local_models": total_models,
        "best_latency_ms": round(best_latency, 2) if is_ready else None,
        "recommended_model": recommended_model,
        "recommendation": (
            f"Local fallback ready with engines: {', '.join(available_engines)}."
            if is_ready
            else "No local inference servers running on 11434, 8080, or 8000; fall back to cloud API."
        ),
    }


def _action_benchmark_ping(host: str, port: Optional[int], timeout: float) -> dict[str, Any]:
    """Measure TCP socket connect latency across local ports."""
    _validate_host(host)
    ports_to_test = [port] if port else [11434, 8080, 8000, 5000]
    pings = []

    for p in ports_to_test:
        connected, latency_ms, err = _tcp_ping(host, p, timeout)
        pings.append({
            "host": host,
            "port": p,
            "connected": connected,
            "latency_ms": round(latency_ms, 2),
            "error": err,
        })

    return {
        "host": host,
        "pings": pings,
        "open_ports": [item["port"] for item in pings if item["connected"]],
    }


def local_llm_probe(arguments: dict[str, Any], context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Operator tool entrypoint for local_llm_probe."""
    if not isinstance(arguments, dict):
        return _envelope_error("Arguments must be a dictionary.")

    action = arguments.get("action")
    if not action or action not in VALID_ACTIONS:
        return _envelope_error(
            f"Invalid or missing action '{action}'. Valid actions: {sorted(VALID_ACTIONS)}"
        )

    try:
        host = str(arguments.get("host") or DEFAULT_HOST).strip()
        # SSRF guardrail: every action is strictly restricted to loopback
        # (validate_host also case-folds the host for consistent output).
        host = _validate_host(host)
        port = int(arguments["port"]) if "port" in arguments and arguments["port"] is not None else None
        timeout = float(arguments.get("timeout", DEFAULT_TIMEOUT))
        if timeout < 0.1:
            timeout = 0.1
        elif timeout > 30.0:
            timeout = 30.0

        endpoints = arguments.get("endpoints")

        if action == "probe_endpoints":
            ep_list = endpoints if isinstance(endpoints, list) and endpoints else [
                f"http://{host}:11434/api/tags",
                f"http://{host}:8080/health",
                f"http://{host}:8000/v1/models",
            ]
            data = _action_probe_endpoints(ep_list, timeout)
            return _envelope_success(data)

        elif action == "get_model_info":
            # Probe ollama or localai
            target_port = port or DEFAULT_PORTS["ollama"]
            data = _action_probe_ollama(host, target_port, timeout)
            return _envelope_success(data)

        elif action == "check_readiness":
            data = _action_check_readiness(host, timeout)
            return _envelope_success(data)

        elif action == "probe_all":
            data = _action_probe_all(host, timeout)
            return _envelope_success(data)

        elif action == "probe_ollama":
            target_port = port or DEFAULT_PORTS["ollama"]
            data = _action_probe_ollama(host, target_port, timeout)
            return _envelope_success(data)

        elif action == "probe_llama_server":
            target_port = port or DEFAULT_PORTS["llama_server"]
            data = _action_probe_llama_server(host, target_port, timeout)
            return _envelope_success(data)

        elif action == "probe_localai":
            target_port = port or DEFAULT_PORTS["localai"]
            data = _action_probe_localai(host, target_port, timeout)
            return _envelope_success(data)

        elif action == "benchmark_ping":
            data = _action_benchmark_ping(host, port, timeout)
            return _envelope_success(data)

        else:
            return _envelope_error(f"Action '{action}' is not supported.")

    except Exception as exc:
        return _envelope_error(exc)


TOOL = {
    "name": "local_llm_probe",
    "description": (
        "Zero-dependency health probing, performance telemetry, and model discovery "
        "for local LLM inference engines (Ollama, llama.cpp, LocalAI). "
        "Monitors VRAM usage, active models, slot capacity, and loopback REST latency."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "probe_endpoints",
                    "get_model_info",
                    "check_readiness",
                    "probe_all",
                    "probe_ollama",
                    "probe_llama_server",
                    "probe_localai",
                    "benchmark_ping",
                ],
                "description": "Probing action to execute.",
            },
            "host": {
                "type": "string",
                "description": "Loopback host address (default: '127.0.0.1').",
            },
            "port": {
                "type": "integer",
                "description": "Target service port (e.g. 11434 for Ollama, 8080 for llama-server).",
            },
            "timeout": {
                "type": "number",
                "description": "HTTP request timeout in seconds (default: 2.0).",
            },
            "endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of HTTP endpoints to probe for probe_endpoints.",
            },
            "model": {
                "type": "string",
                "description": "Optional model name identifier to inspect.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": local_llm_probe,
    "approval": False,
}
