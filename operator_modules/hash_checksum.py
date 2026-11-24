"""Pure standard library cryptographic hashing, HMAC computation, checksum verification, and manifest validation."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from pathlib import Path
from typing import Any

try:
    import operator_tools
except ImportError:
    operator_tools = None  # type: ignore

CHUNK_SIZE = 64 * 1024  # 64 KB
MAX_FILE_BYTES = 1024 * 1024 * 1024  # 1 GB
MAX_TEXT_BYTES = 10 * 1024 * 1024  # 10 MB

ALLOWED_ALGORITHMS: set[str] = {
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s"
}

HASH_LEN_TO_ALGO: dict[int, str] = {
    32: "md5",
    40: "sha1",
    56: "sha224",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}

# Regex for standard sha256sum line: "<hash> [* ]<filepath>"
RE_MANIFEST_LINE = re.compile(r"^([a-fA-F0-9]{32,128})\s+[\* ]?(.+)$")
# Regex for BSD format: "SHA256 (filename) = <hash>"
RE_BSD_MANIFEST = re.compile(r"^([A-Za-z0-9_-]+)\s*\((.+)\)\s*=\s*([a-fA-F0-9]{32,128})$")


def _get_hasher(algo_name: str) -> Any:
    """Return a hashlib hasher for the specified whitelisted algorithm."""
    algo = algo_name.strip().lower()
    if algo not in ALLOWED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algo_name!r}. Whitelisted algorithms: {', '.join(sorted(ALLOWED_ALGORITHMS))}."
        )
    return getattr(hashlib, algo)()


def _safe_resolve_path(raw_path: str, base_dir: Path | None = None) -> Path:
    """Validate and canonicalize path against allowed roots and sensitive targets."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("Path parameter must be a non-empty string.")
    if len(raw_path) > 4096:
        raise ValueError("File path exceeds maximum length.")

    expanded = Path(raw_path).expanduser()
    if not expanded.is_absolute() and base_dir is not None:
        expanded = base_dir / expanded

    if any(part in ("..", "") for part in expanded.parts):
        raise PermissionError(f"Directory traversal sequences not allowed: {raw_path}")

    try:
        resolved = Path(os.path.realpath(str(expanded)))
    except (OSError, ValueError):
        resolved = expanded.resolve()

    if operator_tools is not None:
        if not operator_tools._inside(resolved):
            raise PermissionError(f"Path outside allowed roots: {resolved}")
        if operator_tools.is_sensitive(resolved) or operator_tools.is_credential_target(resolved):
            raise PermissionError(f"Access to sensitive or credential target is blocked: {resolved}")
    else:
        home = Path.home().resolve()
        tmp = Path("/tmp").resolve()
        allowed = (
            resolved == home or resolved.is_relative_to(home) or
            resolved == tmp or resolved.is_relative_to(tmp)
        )
        if not allowed:
            raise PermissionError(f"Path outside allowed directories: {resolved}")

    if not resolved.is_file():
        raise FileNotFoundError(f"File not found: {resolved}")

    size = resolved.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"File exceeds maximum allowed size of 1 GB ({size} bytes).")

    return resolved


def _hash_file_stream(path: Path, algo_name: str) -> tuple[str, int]:
    """Stream file in 64 KB chunks and return (hex_digest, total_bytes)."""
    hasher = _get_hasher(algo_name)
    total_bytes = 0
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
            total_bytes += len(chunk)
            if total_bytes > MAX_FILE_BYTES:
                raise ValueError("File exceeded maximum streaming limit of 1 GB during reading.")
    return hasher.hexdigest(), total_bytes


def _hmac_file_stream(path: Path, key: bytes, algo_name: str) -> tuple[str, int]:
    """Stream file in 64 KB chunks into HMAC and return (hex_digest, total_bytes)."""
    algo = algo_name.strip().lower()
    if algo not in ALLOWED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm for HMAC: {algo_name!r}")
    h = hmac.new(key, digestmod=algo)
    total_bytes = 0
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
            total_bytes += len(chunk)
            if total_bytes > MAX_FILE_BYTES:
                raise ValueError("File exceeded maximum streaming limit of 1 GB during reading.")
    return h.hexdigest(), total_bytes


def hash_checksum(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Cryptographic hashing, HMAC generation, constant-time verification, and checksum manifest verification."""
    del context
    try:
        args = arguments or {}
        action = str(args.get("action") or "").strip().lower()
        if not action:
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required 'action' parameter."}

        algo = str(args.get("algorithm") or "sha256").strip().lower()
        if algo not in ALLOWED_ALGORITHMS:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": f"Unsupported algorithm: {algo!r}. Supported algorithms: {', '.join(sorted(ALLOWED_ALGORITHMS))}.",
            }

        text = args.get("text")
        path_arg = args.get("path")

        if action == "hash_text":
            if text is None or not isinstance(text, str):
                return {"ok": False, "success": False, "data": None, "result": None, "error": "Parameter 'text' must be a string."}
            encoded = text.encode("utf-8")
            if len(encoded) > MAX_TEXT_BYTES:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": f"Input text exceeds maximum limit of {MAX_TEXT_BYTES} bytes ({len(encoded)} bytes).",
                }
            hasher = _get_hasher(algo)
            hasher.update(encoded)
            digest = hasher.hexdigest()
            payload = {
                "algorithm": algo,
                "hash": digest,
                "length_bytes": len(encoded),
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "hash_file":
            if not path_arg or not isinstance(path_arg, str):
                return {"ok": False, "success": False, "data": None, "result": None, "error": "Parameter 'path' must be a non-empty string."}
            resolved = _safe_resolve_path(path_arg)
            digest, total_bytes = _hash_file_stream(resolved, algo)
            payload = {
                "algorithm": algo,
                "hash": digest,
                "file": str(resolved),
                "size_bytes": total_bytes,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "hmac":
            key = args.get("key")
            if not key or not isinstance(key, str):
                return {"ok": False, "success": False, "data": None, "result": None, "error": "Parameter 'key' must be a non-empty string."}
            key_bytes = key.encode("utf-8")

            if text is not None:
                if not isinstance(text, str):
                    return {"ok": False, "success": False, "data": None, "result": None, "error": "Parameter 'text' must be a string."}
                data_bytes = text.encode("utf-8")
                if len(data_bytes) > MAX_TEXT_BYTES:
                    return {"ok": False, "success": False, "data": None, "result": None, "error": f"Text exceeds limit of {MAX_TEXT_BYTES} bytes."}
                h = hmac.new(key_bytes, data_bytes, digestmod=algo)
                payload = {
                    "algorithm": algo,
                    "hmac": h.hexdigest(),
                    "target": "text",
                    "length_bytes": len(data_bytes),
                }
                return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

            elif path_arg is not None:
                resolved = _safe_resolve_path(str(path_arg))
                digest, total_bytes = _hmac_file_stream(resolved, key_bytes, algo)
                payload = {
                    "algorithm": algo,
                    "hmac": digest,
                    "target": "file",
                    "file": str(resolved),
                    "size_bytes": total_bytes,
                }
                return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

            else:
                return {"ok": False, "success": False, "data": None, "result": None, "error": "Either 'text' or 'path' must be provided for HMAC computation."}

        elif action == "verify":
            expected_hash = args.get("expected_hash")
            if not expected_hash or not isinstance(expected_hash, str):
                return {"ok": False, "success": False, "data": None, "result": None, "error": "Parameter 'expected_hash' must be a non-empty string."}

            if text is not None:
                if not isinstance(text, str):
                    return {"ok": False, "success": False, "data": None, "result": None, "error": "Parameter 'text' must be a string."}
                hasher = _get_hasher(algo)
                hasher.update(text.encode("utf-8"))
                actual_hash = hasher.hexdigest()
            elif path_arg is not None:
                resolved = _safe_resolve_path(str(path_arg))
                actual_hash, _ = _hash_file_stream(resolved, algo)
            else:
                return {"ok": False, "success": False, "data": None, "result": None, "error": "Either 'text' or 'path' must be provided for verification."}

            expected_clean = expected_hash.strip().lower()
            matches = hmac.compare_digest(actual_hash.lower(), expected_clean)

            payload = {
                "matches": matches,
                "actual_hash": actual_hash,
                "expected_hash": expected_clean,
                "algorithm": algo,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "verify_checksums":
            manifest_text = args.get("checksums_text")
            base_dir = Path.cwd()

            if path_arg and isinstance(path_arg, str):
                try:
                    p = Path(path_arg).expanduser()
                    base_dir = p.parent.resolve()
                except Exception:
                    base_dir = Path.cwd()

            if not manifest_text:
                if not path_arg or not isinstance(path_arg, str):
                    return {
                        "ok": False,
                        "success": False,
                        "data": None,
                        "result": None,
                        "error": "Either 'checksums_text' or 'path' must be provided for verify_checksums.",
                    }
                resolved_manifest = _safe_resolve_path(path_arg)
                base_dir = resolved_manifest.parent
                manifest_text = resolved_manifest.read_text(encoding="utf-8", errors="replace")

            results = []
            passed_count = 0
            failed_count = 0

            for line in manifest_text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                expected = None
                target_filename = None
                detected_algo = algo

                m_std = RE_MANIFEST_LINE.match(line)
                m_bsd = RE_BSD_MANIFEST.match(line)

                if m_std:
                    expected = m_std.group(1).lower()
                    target_filename = m_std.group(2).strip()
                    # Infer algorithm if standard length matches
                    detected_algo = HASH_LEN_TO_ALGO.get(len(expected), algo)
                elif m_bsd:
                    bsd_algo = m_bsd.group(1).lower()
                    target_filename = m_bsd.group(2).strip()
                    expected = m_bsd.group(3).lower()
                    if bsd_algo in ALLOWED_ALGORITHMS:
                        detected_algo = bsd_algo
                else:
                    results.append({
                        "line": line,
                        "status": "MALFORMED_LINE",
                        "error": "Could not parse checksum line",
                    })
                    failed_count += 1
                    continue

                try:
                    resolved_target = _safe_resolve_path(target_filename, base_dir=base_dir)
                    actual_digest, _ = _hash_file_stream(resolved_target, detected_algo)
                    matched = hmac.compare_digest(actual_digest.lower(), expected)
                    if matched:
                        results.append({
                            "file": target_filename,
                            "status": "OK",
                            "algorithm": detected_algo,
                            "hash": actual_digest,
                        })
                        passed_count += 1
                    else:
                        results.append({
                            "file": target_filename,
                            "status": "FAILED",
                            "algorithm": detected_algo,
                            "expected": expected,
                            "actual": actual_digest,
                        })
                        failed_count += 1
                except FileNotFoundError:
                    results.append({
                        "file": target_filename,
                        "status": "MISSING",
                        "error": "Target file does not exist",
                    })
                    failed_count += 1
                except PermissionError as p_err:
                    results.append({
                        "file": target_filename,
                        "status": "FORBIDDEN",
                        "error": str(p_err),
                    })
                    failed_count += 1
                except Exception as ex:
                    results.append({
                        "file": target_filename,
                        "status": "ERROR",
                        "error": f"{type(ex).__name__}: {ex}",
                    })
                    failed_count += 1

            payload = {
                "total": len(results),
                "passed": passed_count,
                "failed": failed_count,
                "all_ok": (failed_count == 0 and passed_count > 0),
                "results": results,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        else:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": f"Unsupported action: {action!r}. Supported actions: hash_text, hash_file, hmac, verify, verify_checksums.",
            }

    except Exception as err:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"{type(err).__name__}: {err}",
        }


TOOL = {
    "name": "hash_checksum",
    "description": (
        "Pure Python cryptographic digests (SHA-256, SHA-512, MD5, Blake2), HMAC calculation, "
        "streaming chunked file hashing (64KB chunks), constant-time comparison, and checksum manifest verification."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["hash_text", "hash_file", "hmac", "verify", "verify_checksums"],
                "description": "Operation to perform.",
            },
            "algorithm": {
                "type": "string",
                "enum": ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s"],
                "description": "Hash algorithm (default: 'sha256').",
            },
            "text": {"type": "string", "description": "Text payload to hash or verify."},
            "path": {"type": "string", "description": "File path to hash, HMAC, or manifest file."},
            "key": {"type": "string", "description": "Secret key for HMAC computation."},
            "expected_hash": {"type": "string", "description": "Expected hex digest for verification."},
            "checksums_text": {"type": "string", "description": "Content of checksum manifest file."},
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": hash_checksum,
    "approval": False,
}
