"""Secret scanner and cryptographic intelligence operator module for Jarvis.

Provides high-precision Shannon entropy scanning (sliding-window and token extraction),
ReDoS-immune pattern detection for cloud credentials, API tokens, and private keys,
X.509 PEM/DER certificate and cryptographic key inspection, and standard cryptographic
utilities using EXCLUSIVELY the Python standard library. Zero external dependencies.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import os
import re
import secrets
import ssl
import string
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any

# =============================================================================
# Security Perimeter & Configuration Boundaries
# =============================================================================

HOME = Path.home().resolve()
ALLOWED_ROOTS: tuple[Path, ...] = (
    HOME,
    Path("/tmp").resolve(),
    Path("/mnt").resolve(),
    Path("/media").resolve(),
)

MAX_INPUT_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
MAX_PBKDF2_ITERATIONS: int = 1_000_000
MIN_PBKDF2_ITERATIONS: int = 1_000
MAX_TOKEN_BYTES: int = 1024
MIN_TOKEN_BYTES: int = 8

# Sensitive directories and credential files that must never be read directly
SENSITIVE_PARTS: frozenset[str] = frozenset({
    ".ssh",
    ".gnupg",
    ".password-store",
    ".aws",
    ".docker",
    ".kube",
    ".hermes",
})

SENSITIVE_NAMES: frozenset[str] = frozenset({
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "shadow",
})

VALID_ACTIONS: frozenset[str] = frozenset({
    "scan_entropy",
    "scan_patterns",
    "audit_pem",
    "crypto_utils",
    # Aliases
    "entropy_scan",
    "calculate_entropy",
    "pattern_match",
    "scan_secrets",
    "pem_audit",
    "inspect_pem",
    "derive_key",
    "generate_token",
    "verify_hmac",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "text",
    "content",
    "data",
    "path",
    "source_path",
    "threshold",
    "entropy_threshold",
    "hex_entropy_threshold",
    "min_length",
    "window_size",
    "step",
    "charset",
    "mode",
    "patterns",
    "redact_matches",
    "operation",
    "nbytes",
    "token_type",
    "token_format",
    "token_length",
    "password",
    "salt",
    "iterations",
    "hash_name",
    "dklen",
    "key_length",
    "kdf_algorithm",
    "key",
    "message",
    "signature",
    "val_a",
    "val_b",
    "encoding",
    "normalize_entropy",
})

# =============================================================================
# Exceptions
# =============================================================================

class SecretScannerError(Exception):
    """Base exception for secret scanner operations."""


class SecurityError(SecretScannerError):
    """Base security violation error."""


class PathSecurityError(SecurityError):
    """Raised when path traversal or forbidden boundary escape is detected."""


class SensitivePathError(SecurityError):
    """Raised when access to a sensitive credential path is attempted."""


class PayloadSizeError(SecretScannerError):
    """Raised when payload or file size exceeds maximum bounded limit."""


class CryptoError(SecretScannerError):
    """Raised when cryptographic parameters or execution fails."""


# =============================================================================
# Return Envelope Helpers
# =============================================================================

def _envelope_success(data: dict[str, Any]) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator success envelope."""
    return {
        "ok": True,
        "success": True,
        "data": data,
        "result": data,
        "error": None,
    }


def _envelope_error(err: str | Exception) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator error envelope."""
    if isinstance(err, Exception):
        msg = f"{type(err).__name__}: {err}"
    else:
        msg = str(err)
    return {
        "ok": False,
        "success": False,
        "data": None,
        "result": None,
        "error": msg,
    }


# =============================================================================
# Path Confinement & Loader Helpers
# =============================================================================

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
    """Check if any path component touches sensitive credential directories or files."""
    parts = [p.casefold() for p in path.parts]
    for part in parts:
        if part in SENSITIVE_PARTS:
            return True
        if part in SENSITIVE_NAMES:
            return True
    if path.name.casefold() in SENSITIVE_NAMES:
        return True
    return False


def _validate_and_resolve_path(path_str: str) -> Path:
    """Resolve and confine a file path, ensuring security invariants."""
    if not isinstance(path_str, str) or not path_str.strip():
        raise ValueError("File path must be a non-empty string.")
    if "\0" in path_str:
        raise PathSecurityError("Null bytes are prohibited in file paths.")

    parts = Path(path_str).parts
    if ".." in parts:
        resolved_test = Path(os.path.realpath(os.path.expanduser(path_str)))
        if not _is_inside_allowed_roots(resolved_test):
            raise PathSecurityError(f"Path traversal escape detected: '{path_str}'")

    resolved = Path(os.path.realpath(os.path.expanduser(path_str)))

    if not _is_inside_allowed_roots(resolved):
        raise PathSecurityError(f"Path '{path_str}' resolves outside ALLOWED_ROOTS.")

    if _is_sensitive_path(resolved):
        raise SensitivePathError(f"Access to sensitive path '{resolved}' is restricted.")

    if not resolved.exists():
        raise FileNotFoundError(f"File not found: '{path_str}'")

    if not resolved.is_file():
        raise ValueError(f"Path '{path_str}' is not a regular file.")

    st = resolved.stat()
    if st.st_size > MAX_INPUT_BYTES:
        raise PayloadSizeError(
            f"File size ({st.st_size} bytes) exceeds maximum allowed size ({MAX_INPUT_BYTES} bytes)."
        )

    return resolved


def _load_input(arguments: dict[str, Any]) -> tuple[str, str | None]:
    """Retrieve content string from either 'text'/'content'/'data' or 'path'/'source_path'."""
    content = arguments.get("text")
    if content is None:
        content = arguments.get("content")
    if content is None:
        content = arguments.get("data")

    path_str = arguments.get("path") or arguments.get("source_path")

    if content is not None:
        if not isinstance(content, str):
            raise ValueError("'text' must be a string.")
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > MAX_INPUT_BYTES:
            raise PayloadSizeError(
                f"Content size ({len(content_bytes)} bytes) exceeds maximum limit ({MAX_INPUT_BYTES} bytes)."
            )
        return content, str(path_str) if path_str else None

    if path_str is not None:
        resolved = _validate_and_resolve_path(path_str)
        try:
            encoding = arguments.get("encoding", "utf-8") or "utf-8"
            text = resolved.read_text(encoding=encoding, errors="replace")
            return text, str(resolved)
        except OSError as exc:
            raise SecretScannerError(f"Failed to read file '{resolved}': {exc}") from exc

    return "", None


# =============================================================================
# Secret Redaction Helper
# =============================================================================

def mask_secret(secret: str, prefix_len: int = 4, suffix_len: int = 4) -> str:
    """Mask secret token, retaining minimal prefix and suffix characters."""
    if not secret:
        return "[EMPTY]"
    if len(secret) <= prefix_len + suffix_len:
        return "[REDACTED]"
    return f"{secret[:prefix_len]}...[REDACTED]...{secret[-suffix_len:]}"


# =============================================================================
# Feature 25: Shannon Entropy Engine
# =============================================================================

def shannon_entropy(data: str, normalize: bool = False) -> float:
    """Calculate exact Shannon entropy in bits per symbol: H(X) = -sum(p * log2(p))."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    h = -sum((c / n) * math.log2(c / n) for c in counts.values())
    if normalize:
        alphabet_size = len(counts)
        if alphabet_size > 1:
            h = h / math.log2(alphabet_size)
        else:
            h = 0.0
    return h


def _do_scan_entropy(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute Shannon entropy scanning across text or file."""
    text, source_path = _load_input(arguments)
    threshold_arg = arguments.get("threshold")
    if threshold_arg is None:
        threshold_arg = arguments.get("entropy_threshold")

    hex_threshold = float(arguments.get("hex_entropy_threshold", 3.2))
    base_threshold = float(threshold_arg) if threshold_arg is not None else 4.5
    min_length = int(arguments.get("min_length", 16))
    window_size = int(arguments.get("window_size", 32))
    step = max(1, int(arguments.get("step", 8)))
    charset_filter = str(arguments.get("charset", "all")).lower()
    mode = str(arguments.get("mode", "token")).lower()
    normalize = bool(arguments.get("normalize_entropy", False))

    if not text:
        payload = {
            "action": arguments.get("action", "scan_entropy"),
            "clean": True,
            "scanned_bytes": 0,
            "overall_entropy": 0.0,
            "findings_count": 0,
            "matches_count": 0,
            "high_entropy_tokens": [],
            "findings": [],
            "source_path": source_path,
        }
        return _envelope_success(payload)

    scanned_bytes = len(text.encode("utf-8"))
    overall_entropy = round(shannon_entropy(text, normalize=normalize), 4)
    findings: list[dict[str, Any]] = []

    hex_re = re.compile(r"^[0-9a-fA-F]+$")
    b64_re = re.compile(r"^[A-Za-z0-9+/=_-]+$")

    if mode == "sliding_window":
        lines = text.splitlines()
        for line_no, line in enumerate(lines, 1):
            line_len = len(line)
            if line_len < min_length:
                continue
            effective_window = min(window_size, line_len)
            for offset in range(0, line_len - effective_window + 1, step):
                chunk = line[offset : offset + effective_window]
                is_hex = bool(hex_re.match(chunk))
                is_b64 = bool(b64_re.match(chunk))

                if charset_filter == "hex" and not is_hex:
                    continue
                if charset_filter == "base64" and not is_b64:
                    continue

                eff_thresh = hex_threshold if is_hex else base_threshold
                ent = shannon_entropy(chunk, normalize=normalize)
                if ent >= eff_thresh:
                    token_charset = "hex" if is_hex else ("base64" if is_b64 else "ascii")
                    token_type = "high_entropy_hex_window" if is_hex else "high_entropy_window"
                    findings.append({
                        "line": line_no,
                        "offset": offset,
                        "entropy": round(ent, 3),
                        "length": effective_window,
                        "type": token_type,
                        "charset": token_charset,
                        "sample": mask_secret(chunk),
                        "high_entropy_token": mask_secret(chunk),
                    })
    else:
        # Token extraction mode
        token_pattern = re.compile(r"[A-Za-z0-9+/=_\-.]{" + str(min_length) + r",}")
        lines = text.splitlines()
        for line_no, line in enumerate(lines, 1):
            for match in token_pattern.finditer(line):
                token = match.group(0)
                t_len = len(token)
                is_hex = bool(hex_re.match(token))
                is_b64 = bool(b64_re.match(token))

                if charset_filter == "hex" and not is_hex:
                    continue
                if charset_filter == "base64" and not is_b64:
                    continue

                token_charset = "hex" if is_hex else ("base64" if is_b64 else "ascii")
                # Adaptive thresholding
                if threshold_arg is not None:
                    eff_thresh = base_threshold
                elif is_hex:
                    eff_thresh = hex_threshold
                elif is_b64:
                    eff_thresh = 4.3
                else:
                    eff_thresh = 4.5

                ent = shannon_entropy(token, normalize=normalize)
                if ent >= eff_thresh:
                    findings.append({
                        "line": line_no,
                        "entropy": round(ent, 3),
                        "length": t_len,
                        "type": "high_entropy_hex" if is_hex else "high_entropy_token",
                        "charset": token_charset,
                        "sample": mask_secret(token),
                        "high_entropy_token": mask_secret(token),
                    })
                    continue

                # Sliding window fallback inside long tokens
                if t_len > window_size:
                    for start in range(0, t_len - window_size + 1, step):
                        window = token[start : start + window_size]
                        w_hex = bool(hex_re.match(window))
                        w_thresh = hex_threshold if w_hex else (4.3 if is_b64 else base_threshold)
                        w_ent = shannon_entropy(window, normalize=normalize)
                        if w_ent >= w_thresh:
                            findings.append({
                                "line": line_no,
                                "offset": start,
                                "entropy": round(w_ent, 3),
                                "length": window_size,
                                "type": "high_entropy_hex_window" if w_hex else "high_entropy_window",
                                "charset": "hex" if w_hex else token_charset,
                                "sample": mask_secret(window),
                                "high_entropy_token": mask_secret(window),
                            })
                            break

    payload = {
        "action": arguments.get("action", "scan_entropy"),
        "clean": len(findings) == 0,
        "scanned_bytes": scanned_bytes,
        "overall_entropy": overall_entropy,
        "findings_count": len(findings),
        "matches_count": len(findings),
        "high_entropy_tokens": findings,
        "findings": findings,
        "source_path": source_path,
    }
    return _envelope_success(payload)


# =============================================================================
# Feature 26: Pattern Matching for High-Value Secrets
# =============================================================================

# ReDoS-hardened patterns: linear matching time, zero nested quantifiers
SECRET_PATTERNS: dict[str, tuple[re.Pattern, str, str]] = {
    "aws_access_key": (
        re.compile(r"\b(A[SK]IA[0-9A-Z]{16})\b"),
        "CRITICAL",
        "aws",
    ),
    "aws_secret_key": (
        re.compile(r"(?i)\b(?:aws_secret_access_key|aws_secret_key|aws_secret|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "CRITICAL",
        "aws",
    ),
    "github_token": (
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82,})\b"),
        "CRITICAL",
        "github",
    ),
    "ssh_private_key": (
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "CRITICAL",
        "private_key",
    ),
    "openai_api_key": (
        re.compile(r"\b(sk-(?:proj-|admin-)?[A-Za-z0-9_-]{20,})\b"),
        "CRITICAL",
        "openai",
    ),
    "slack_token": (
        re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b"),
        "HIGH",
        "slack",
    ),
    "jwt_token": (
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        "HIGH",
        "jwt",
    ),
    "credential_assignment": (
        re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*['\"]([A-Za-z0-9+/=_\-]{16,})['\"]"),
        "HIGH",
        "generic",
    ),
}

KNOWN_PATTERN_GROUPS = frozenset({
    "aws",
    "github",
    "ssh_private_key",
    "private_key",
    "openai",
    "slack",
    "jwt",
    "generic",
    "credential_assignment",
})


def _do_scan_patterns(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute ReDoS-hardened regex pattern detection for secrets."""
    text, source_path = _load_input(arguments)
    requested_patterns = arguments.get("patterns")
    redact_matches = bool(arguments.get("redact_matches", True))

    active_patterns: dict[str, tuple[re.Pattern, str, str]] = {}
    if requested_patterns:
        norm_requested = {str(p).lower() for p in requested_patterns}
        invalid = norm_requested - KNOWN_PATTERN_GROUPS
        if invalid:
            raise ValueError(f"Invalid pattern group(s): {sorted(invalid)}. Allowed: {sorted(KNOWN_PATTERN_GROUPS)}")

        for pat_name, (regex, sev, grp) in SECRET_PATTERNS.items():
            if grp in norm_requested or pat_name in norm_requested:
                active_patterns[pat_name] = (regex, sev, grp)
            elif "private_key" in norm_requested and grp == "private_key":
                active_patterns[pat_name] = (regex, sev, grp)
            elif "credential_assignment" in norm_requested and grp == "generic":
                active_patterns[pat_name] = (regex, sev, grp)
    else:
        active_patterns = SECRET_PATTERNS

    if not text:
        payload = {
            "action": arguments.get("action", "scan_patterns"),
            "clean": True,
            "scanned_bytes": 0,
            "findings_count": 0,
            "findings": [],
            "source_path": source_path,
        }
        return _envelope_success(payload)

    scanned_bytes = len(text.encode("utf-8"))
    findings: list[dict[str, Any]] = []

    lines = text.splitlines()
    for line_no, line in enumerate(lines, 1):
        for pat_name, (regex, severity, _) in active_patterns.items():
            for match in regex.finditer(line):
                # If groups exist, use group 1 (actual token), otherwise full match
                matched_val = match.group(1) if match.groups() else match.group(0)
                display_val = mask_secret(matched_val) if redact_matches else matched_val
                findings.append({
                    "line": line_no,
                    "type": pat_name,
                    "pattern_name": pat_name,
                    "match_preview": display_val,
                    "masked_value": display_val,
                    "severity": severity,
                })

    payload = {
        "action": arguments.get("action", "scan_patterns"),
        "clean": len(findings) == 0,
        "scanned_bytes": scanned_bytes,
        "findings_count": len(findings),
        "findings": findings,
        "source_path": source_path,
    }
    return _envelope_success(payload)


# =============================================================================
# Feature 27: PEM / X.509 Audit Engine (Pure Stdlib)
# =============================================================================

PEM_BLOCK_RE = re.compile(
    r"-----BEGIN ([A-Z0-9 -]+)-----\r?\n([A-Za-z0-9+/=\s]+?)\r?\n-----END \1-----",
    re.MULTILINE,
)

OID_MAP = {
    "1.2.840.113549.1.1.1": ("RSA", 0),
    "1.2.840.10045.2.1": ("EC", 0),
    "1.2.840.10045.3.1.7": ("prime256v1", 256),
    "1.3.132.0.34": ("secp384r1", 384),
    "1.3.132.0.35": ("secp521r1", 521),
    "1.3.101.112": ("Ed25519", 256),
    "1.3.101.113": ("Ed448", 448),
}


def _parse_der_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int] | None:
    """Parse a single ASN.1 DER Tag-Length-Value entry."""
    if offset >= len(data):
        return None
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        return None
    length_byte = data[offset]
    offset += 1
    if length_byte < 0x80:
        length = length_byte
    else:
        num_len_bytes = length_byte & 0x7F
        if num_len_bytes == 0 or offset + num_len_bytes > len(data):
            return None
        length = int.from_bytes(data[offset : offset + num_len_bytes], "big")
        offset += num_len_bytes
    if offset + length > len(data):
        return None
    value = data[offset : offset + length]
    return tag, value, offset + length


def _decode_oid(data: bytes) -> str:
    """Decode DER Object Identifier bytes into dotted string."""
    if not data:
        return ""
    first = data[0]
    components = [first // 40, first % 40]
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            components.append(val)
            val = 0
    return ".".join(str(c) for c in components)


def _inspect_key_der(der_bytes: bytes, block_type: str) -> dict[str, Any]:
    """Inspect ASN.1 DER key structure for key type and bit length."""
    info: dict[str, Any] = {
        "valid": True,
        "key_type": "Unknown",
        "key_format": block_type,
        "key_size_bits": None,
        "is_encrypted": False,
    }

    if "ENCRYPTED" in block_type:
        info["is_encrypted"] = True
        info["key_type"] = "Encrypted"
        return info

    if "OPENSSH" in block_type:
        info["key_type"] = "OpenSSH"
        info["is_encrypted"] = b"bcrypt" in der_bytes or b"aes256" in der_bytes
        return info

    try:
        tlv = _parse_der_tlv(der_bytes, 0)
        if not tlv or tlv[0] != 0x30:  # Must start with SEQUENCE
            info["valid"] = False
            info["error"] = "Invalid DER: expected SEQUENCE root"
            return info

        seq_bytes = tlv[1]

        # PKCS#1 RSA Private Key check: SEQUENCE { INTEGER (version), INTEGER (modulus), ... }
        if "RSA PRIVATE KEY" in block_type:
            p1 = _parse_der_tlv(seq_bytes, 0)
            if p1 and p1[0] == 0x02:  # version INTEGER
                p2 = _parse_der_tlv(seq_bytes, p1[2])
                if p2 and p2[0] == 0x02:  # modulus INTEGER
                    mod_bytes = p2[1].lstrip(b"\x00")
                    bit_len = int.from_bytes(mod_bytes, "big").bit_length()
                    info["key_type"] = "RSA"
                    info["key_format"] = "PKCS#1"
                    info["key_size_bits"] = bit_len
                    return info

        # PKCS#8 PrivateKeyInfo: SEQUENCE { INTEGER (version), AlgorithmIdentifier, OCTET STRING }
        p_version = _parse_der_tlv(seq_bytes, 0)
        if p_version and p_version[0] == 0x02:
            p_alg = _parse_der_tlv(seq_bytes, p_version[2])
            if p_alg and p_alg[0] == 0x30:  # AlgorithmIdentifier SEQUENCE
                alg_seq = p_alg[1]
                p_oid = _parse_der_tlv(alg_seq, 0)
                if p_oid and p_oid[0] == 0x06:  # OBJECT IDENTIFIER
                    oid_str = _decode_oid(p_oid[1])
                    oid_name, bit_hint = OID_MAP.get(oid_str, (oid_str, None))
                    info["key_type"] = oid_name
                    info["key_format"] = "PKCS#8"

                    # If RSA, unpack inner OCTET STRING (which wraps PKCS#1)
                    if oid_name == "RSA":
                        p_oct = _parse_der_tlv(seq_bytes, p_alg[2])
                        if p_oct and p_oct[0] == 0x04:  # OCTET STRING
                            inner_tlv = _parse_der_tlv(p_oct[1], 0)
                            if inner_tlv and inner_tlv[0] == 0x30:
                                ip1 = _parse_der_tlv(inner_tlv[1], 0)
                                if ip1 and ip1[0] == 0x02:
                                    ip2 = _parse_der_tlv(inner_tlv[1], ip1[2])
                                    if ip2 and ip2[0] == 0x02:
                                        mod_bytes = ip2[1].lstrip(b"\x00")
                                        info["key_size_bits"] = int.from_bytes(mod_bytes, "big").bit_length()
                    elif bit_hint:
                        info["key_size_bits"] = bit_hint
                    return info
    except Exception as exc:
        info["valid"] = False
        info["error"] = f"DER parsing error: {exc}"

    return info


def _do_audit_pem(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute X.509 and PEM block inspection across certificates and keys."""
    text, source_path = _load_input(arguments)

    if not text:
        payload = {
            "action": arguments.get("action", "audit_pem"),
            "blocks_count": 0,
            "blocks": [],
            "has_expired": False,
            "has_private_key": False,
            "source_path": source_path,
        }
        return _envelope_success(payload)

    # Detect mismatched headers or corrupted blocks first
    raw_begins = re.findall(r"-----BEGIN ([A-Z0-9 -]+)-----", text)
    raw_ends = re.findall(r"-----END ([A-Z0-9 -]+)-----", text)
    if raw_begins != raw_ends:
        # Mismatched blocks
        block_entry = {
            "block_type": raw_begins[0] if raw_begins else "UNKNOWN",
            "valid": False,
            "error": "Mismatched PEM BEGIN/END headers",
        }
        payload = {
            "action": arguments.get("action", "audit_pem"),
            "blocks_count": 1,
            "blocks": [block_entry],
            "has_expired": False,
            "has_private_key": False,
            "source_path": source_path,
        }
        return _envelope_success(payload)

    matches = list(PEM_BLOCK_RE.finditer(text))
    if not matches and raw_begins:
        # PEM headers exist but regex failed due to corrupted body/format
        block_entry = {
            "block_type": raw_begins[0],
            "valid": False,
            "error": "Corrupted or malformed PEM block content",
        }
        payload = {
            "action": arguments.get("action", "audit_pem"),
            "blocks_count": 1,
            "blocks": [block_entry],
            "has_expired": False,
            "has_private_key": False,
            "source_path": source_path,
        }
        return _envelope_success(payload)

    blocks: list[dict[str, Any]] = []
    has_expired = False
    has_private_key = False

    for m in matches:
        b_type = m.group(1).strip()
        b_body = m.group(2).strip()

        # Attempt Base64 decode
        try:
            der_bytes = base64.b64decode("".join(b_body.split()), validate=True)
        except Exception as exc:
            blocks.append({
                "block_type": b_type,
                "valid": False,
                "error": f"Base64 decoding failed: {exc}",
            })
            continue

        if "PRIVATE KEY" in b_type:
            has_private_key = True
            key_info = _inspect_key_der(der_bytes, b_type)
            blocks.append({
                "block_type": b_type,
                **key_info,
            })
        elif "PUBLIC KEY" in b_type:
            key_info = _inspect_key_der(der_bytes, b_type)
            blocks.append({
                "block_type": b_type,
                **key_info,
            })
        elif "CERTIFICATE" in b_type:
            # Audit X.509 Certificate using stdlib ssl._ssl._test_decode_cert
            pem_single = f"-----BEGIN {b_type}-----\n{b_body}\n-----END {b_type}-----\n"
            temp_file = None
            try:
                with tempfile.NamedTemporaryFile("w", dir="/tmp", delete=False) as tf:
                    temp_file = tf.name
                    tf.write(pem_single)

                cert_dict = ssl._ssl._test_decode_cert(temp_file)
                not_after_str = cert_dict.get("notAfter", "")
                not_before_str = cert_dict.get("notBefore", "")

                days_left = 0.0
                is_expired = False
                if not_after_str:
                    try:
                        exp_epoch = ssl.cert_time_to_seconds(not_after_str)
                        now_epoch = time.time()
                        days_left = round((exp_epoch - now_epoch) / 86400.0, 2)
                        is_expired = days_left <= 0.0
                        if is_expired:
                            has_expired = True
                    except Exception:
                        pass

                subj = cert_dict.get("subject", ())
                issuer = cert_dict.get("issuer", ())
                is_self_signed = (subj == issuer and bool(subj))

                blocks.append({
                    "block_type": b_type,
                    "valid": True,
                    "subject": subj,
                    "issuer": issuer,
                    "version": cert_dict.get("version"),
                    "serial": cert_dict.get("serialNumber"),
                    "serialNumber": cert_dict.get("serialNumber"),
                    "not_before": not_before_str,
                    "not_after": not_after_str,
                    "days_left": days_left,
                    "days_remaining": days_left,
                    "is_expired": is_expired,
                    "is_self_signed": is_self_signed,
                    "subjectAltName": cert_dict.get("subjectAltName", ()),
                })
            except Exception as exc:
                blocks.append({
                    "block_type": b_type,
                    "valid": False,
                    "error": f"Certificate parsing failed: {exc}",
                })
            finally:
                if temp_file and os.path.exists(temp_file):
                    try:
                        os.unlink(temp_file)
                    except OSError:
                        pass
        else:
            blocks.append({
                "block_type": b_type,
                "valid": True,
                "notes": "Non-standard PEM block type",
            })

    payload = {
        "action": arguments.get("action", "audit_pem"),
        "blocks_count": len(blocks),
        "blocks": blocks,
        "has_expired": has_expired,
        "has_private_key": has_private_key,
        "source_path": source_path,
    }
    return _envelope_success(payload)


# =============================================================================
# Feature 28: Zero-Dependency Cryptographic Utilities
# =============================================================================

def _do_crypto_utils(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute cryptographic utilities: CSPRNG token, PBKDF2/Scrypt, and HMAC."""
    action = arguments.get("action", "crypto_utils")
    op = arguments.get("operation")
    if not op:
        # Check action name for operation alias
        if action in ("generate_token", "derive_key", "verify_hmac"):
            op = action
        else:
            op = "generate_token"

    if op == "generate_token":
        nbytes_val = arguments.get("nbytes")
        if nbytes_val is None:
            nbytes_val = arguments.get("token_length", 32)
        nbytes = int(nbytes_val)

        if nbytes < MIN_TOKEN_BYTES or nbytes > MAX_TOKEN_BYTES:
            raise ValueError(
                f"nbytes ({nbytes}) must be between {MIN_TOKEN_BYTES} and {MAX_TOKEN_BYTES}."
            )

        token_type = str(arguments.get("token_type") or arguments.get("token_format") or "hex").lower()

        if token_type == "hex":
            token = secrets.token_hex(nbytes)
        elif token_type == "urlsafe":
            token = secrets.token_urlsafe(nbytes)
        elif token_type == "alphanumeric":
            alphabet = string.ascii_letters + string.digits
            token = "".join(secrets.choice(alphabet) for _ in range(nbytes))
        elif token_type == "ascii_printable":
            alphabet = string.ascii_letters + string.digits + string.punctuation
            token = "".join(secrets.choice(alphabet) for _ in range(nbytes))
        else:
            raise ValueError(f"Unsupported token_type '{token_type}'. Allowed: hex, urlsafe, alphanumeric, ascii_printable.")

        payload = {
            "action": "crypto_utils",
            "operation": "generate_token",
            "token": token,
            "token_type": token_type,
            "length": len(token),
            "entropy": round(shannon_entropy(token), 3),
        }
        return _envelope_success(payload)

    elif op in ("derive_key", "pbkdf2", "scrypt"):
        password = arguments.get("password")
        if password is None:
            raise ValueError("'password' is required for key derivation.")
        if not isinstance(password, str):
            raise ValueError("'password' must be a string.")

        salt = arguments.get("salt") or "jarvis_salt"
        if isinstance(salt, str):
            salt_bytes = salt.encode("utf-8")
        else:
            salt_bytes = bytes(salt)

        iterations = int(arguments.get("iterations", 100000))
        if iterations < MIN_PBKDF2_ITERATIONS or iterations > MAX_PBKDF2_ITERATIONS:
            raise ValueError(
                f"iterations ({iterations}) exceeds safety limits (must be between {MIN_PBKDF2_ITERATIONS} and {MAX_PBKDF2_ITERATIONS})."
            )

        dklen = int(arguments.get("dklen") or arguments.get("key_length") or 32)
        if dklen < 16 or dklen > 128:
            raise ValueError(f"dklen ({dklen}) must be between 16 and 128 bytes.")

        kdf_alg = str(arguments.get("kdf_algorithm") or "pbkdf2_sha256").lower()
        hash_name = str(arguments.get("hash_name", "sha256")).lower()

        if op == "scrypt" or kdf_alg == "scrypt":
            key_bytes = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt_bytes,
                n=16384,
                r=8,
                p=1,
                dklen=dklen,
            )
            algorithm_used = "scrypt"
        else:
            eff_hash = "sha512" if "sha512" in kdf_alg else hash_name
            key_bytes = hashlib.pbkdf2_hmac(
                eff_hash,
                password.encode("utf-8"),
                salt_bytes,
                iterations,
                dklen=dklen,
            )
            algorithm_used = f"pbkdf2_{eff_hash}"

        payload = {
            "action": "crypto_utils",
            "operation": "derive_key",
            "derived_key_hex": key_bytes.hex(),
            "derived_key_base64": base64.b64encode(key_bytes).decode("ascii"),
            "algorithm": algorithm_used,
            "iterations": iterations,
            "dklen": dklen,
        }
        return _envelope_success(payload)

    elif op in ("compare_digest", "verify_hmac", "hmac_verify", "hmac_generate"):
        if op == "hmac_generate":
            key = arguments.get("key")
            msg = arguments.get("message")
            if key is None or msg is None:
                raise ValueError("'key' and 'message' are required for hmac_generate.")
            hash_name = str(arguments.get("hash_name", "sha256")).lower()
            digest = hmac.new(
                key.encode("utf-8"),
                msg.encode("utf-8"),
                digestmod=hash_name,
            ).hexdigest()
            payload = {
                "action": "crypto_utils",
                "operation": "hmac_generate",
                "hmac_hex": digest,
                "hash_name": hash_name,
            }
            return _envelope_success(payload)

        elif op in ("verify_hmac", "hmac_verify") and "signature" in arguments:
            key = arguments.get("key", "")
            msg = arguments.get("message", "")
            sig = arguments.get("signature", "")
            hash_name = str(arguments.get("hash_name", "sha256")).lower()
            expected = hmac.new(
                key.encode("utf-8"),
                msg.encode("utf-8"),
                digestmod=hash_name,
            ).hexdigest()
            match = hmac.compare_digest(expected, sig)
            payload = {
                "action": "crypto_utils",
                "operation": "hmac_verify",
                "match": match,
            }
            return _envelope_success(payload)

        else:
            val_a = arguments.get("val_a")
            val_b = arguments.get("val_b")
            # Normalize to strings to prevent TypeError in Python 3.14
            str_a = str(val_a) if val_a is not None else ""
            str_b = str(val_b) if val_b is not None else ""
            match = hmac.compare_digest(str_a, str_b)
            payload = {
                "action": "crypto_utils",
                "operation": "compare_digest",
                "match": match,
            }
            return _envelope_success(payload)

    else:
        raise ValueError(f"Unknown crypto operation '{op}'.")


# =============================================================================
# Handler Entrypoint
# =============================================================================

def secret_scanner(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute secret scanner and cryptographic intelligence actions."""
    try:
        if not isinstance(arguments, dict):
            return _envelope_error(ValueError("Tool arguments must be a dictionary."))

        unknown_args = set(arguments.keys()) - KNOWN_ARGUMENTS
        if unknown_args:
            return _envelope_error(
                ValueError(f"Unknown argument(s) rejected: {', '.join(sorted(unknown_args))}")
            )

        action = arguments.get("action")
        if not action or action not in VALID_ACTIONS:
            return _envelope_error(
                ValueError(f"Invalid or missing action '{action}'. Valid actions: {sorted(VALID_ACTIONS)}")
            )

        if action in ("scan_entropy", "entropy_scan", "calculate_entropy"):
            return _do_scan_entropy(arguments)
        elif action in ("scan_patterns", "pattern_match", "scan_secrets"):
            return _do_scan_patterns(arguments)
        elif action in ("audit_pem", "pem_audit", "inspect_pem"):
            return _do_audit_pem(arguments)
        elif action in ("crypto_utils", "derive_key", "generate_token", "verify_hmac"):
            return _do_crypto_utils(arguments)
        else:
            return _envelope_error(ValueError(f"Unhandled action '{action}'"))
    except Exception as exc:
        return _envelope_error(exc)


# =============================================================================
# Tool Schema Export
# =============================================================================

TOOL = {
    "name": "secret_scanner",
    "description": (
        "Zero-dependency security audit and cryptographic operator for Jarvis: scan text and files for "
        "exposed credentials and high-entropy tokens (Shannon entropy analysis), inspect PEM certificates "
        "and private/public keys, perform standard key derivation (PBKDF2/Scrypt), verify HMAC signatures with "
        "constant-time comparison, and generate cryptographically secure random tokens. Pure standard library "
        "with strict path confinement to ALLOWED_ROOTS (HOME, /tmp, /mnt, /media) and 10 MB bounds."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "scan_entropy",
                    "scan_patterns",
                    "audit_pem",
                    "crypto_utils",
                    "entropy_scan",
                    "pattern_match",
                    "pem_audit",
                    "scan_secrets",
                    "calculate_entropy",
                    "inspect_pem",
                    "derive_key",
                    "generate_token",
                    "verify_hmac",
                ],
                "description": "Security audit or cryptographic action to perform.",
            },
            "text": {
                "type": "string",
                "description": "Inline text payload to scan, analyze for entropy, or parse for PEM blocks.",
            },
            "content": {
                "type": "string",
                "description": "Alias for 'text'.",
            },
            "data": {
                "type": "string",
                "description": "Alias for 'text'.",
            },
            "path": {
                "type": "string",
                "description": "Filesystem path to source file or certificate. Must reside within ALLOWED_ROOTS.",
            },
            "source_path": {
                "type": "string",
                "description": "Alias for 'path'.",
            },
            "threshold": {
                "type": "number",
                "description": "Shannon entropy cutoff threshold (default adaptive: 3.2 for Hex, 4.3 for Base64).",
            },
            "entropy_threshold": {
                "type": "number",
                "description": "Alias for 'threshold'.",
            },
            "hex_entropy_threshold": {
                "type": "number",
                "description": "Entropy threshold for purely hexadecimal tokens (default: 3.2).",
            },
            "min_length": {
                "type": "integer",
                "description": "Minimum token length to inspect during entropy scanning (default: 16).",
            },
            "window_size": {
                "type": "integer",
                "description": "Sliding window character size for entropy scanning (default: 32).",
            },
            "step": {
                "type": "integer",
                "description": "Sliding window step size (default: 8).",
            },
            "charset": {
                "type": "string",
                "enum": ["all", "hex", "base64"],
                "default": "all",
                "description": "Charset filter for entropy candidate tokens.",
            },
            "mode": {
                "type": "string",
                "enum": ["token", "sliding_window"],
                "default": "token",
                "description": "Scanning mode for entropy analysis.",
            },
            "patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Secret patterns to scan: aws, github, private_key, openai, slack, jwt, generic.",
            },
            "redact_matches": {
                "type": "boolean",
                "default": True,
                "description": "Whether to redact matched secret values in output previews (default: true).",
            },
            "operation": {
                "type": "string",
                "enum": ["generate_token", "derive_key", "compare_digest", "pbkdf2", "scrypt", "hmac_generate", "hmac_verify"],
                "description": "Sub-operation when action='crypto_utils'.",
            },
            "nbytes": {
                "type": "integer",
                "description": "Bytes for generate_token (default: 32).",
            },
            "token_type": {
                "type": "string",
                "enum": ["hex", "urlsafe", "alphanumeric", "ascii_printable"],
                "default": "hex",
                "description": "Format for token generation.",
            },
            "token_format": {
                "type": "string",
                "description": "Alias for token_type.",
            },
            "token_length": {
                "type": "integer",
                "description": "Alias for nbytes.",
            },
            "password": {
                "type": "string",
                "description": "Password string for key derivation.",
            },
            "salt": {
                "type": "string",
                "description": "Salt string for key derivation.",
            },
            "iterations": {
                "type": "integer",
                "description": "PBKDF2 iteration count (default: 100000, bounds: 1000 to 1000000).",
            },
            "hash_name": {
                "type": "string",
                "default": "sha256",
                "description": "Hashing algorithm for PBKDF2 or HMAC (default: 'sha256').",
            },
            "dklen": {
                "type": "integer",
                "default": 32,
                "description": "Derived key length in bytes.",
            },
            "key_length": {
                "type": "integer",
                "description": "Alias for dklen.",
            },
            "kdf_algorithm": {
                "type": "string",
                "enum": ["pbkdf2_sha256", "pbkdf2_sha512", "scrypt"],
                "description": "Key derivation algorithm.",
            },
            "key": {
                "type": "string",
                "description": "Key string for HMAC generation or verification.",
            },
            "message": {
                "type": "string",
                "description": "Message string for HMAC generation or verification.",
            },
            "signature": {
                "type": "string",
                "description": "Hex signature for HMAC verification.",
            },
            "val_a": {
                "type": "string",
                "description": "First value for compare_digest.",
            },
            "val_b": {
                "type": "string",
                "description": "Second value for compare_digest.",
            },
            "encoding": {
                "type": "string",
                "default": "utf-8",
                "description": "Encoding for reading files from disk.",
            },
            "normalize_entropy": {
                "type": "boolean",
                "default": False,
                "description": "Normalize Shannon entropy between 0.0 and 1.0.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": secret_scanner,
    "approval": False,
}
