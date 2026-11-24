"""Pure standard library regular expression workbench with ReDoS static analysis and 1.0s timeout guard."""

from __future__ import annotations

import re
import signal
import threading
from typing import Any

MAX_TEXT_BYTES = 512 * 1024  # 512 KB
MAX_PATTERN_LENGTH = 1024
DEFAULT_TIMEOUT_SEC = 1.0
MAX_MATCHES_LIMIT = 500

FLAG_MAP: dict[str, int] = {
    "IGNORECASE": re.IGNORECASE,
    "I": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "M": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "S": re.DOTALL,
    "VERBOSE": re.VERBOSE,
    "X": re.VERBOSE,
}

# Static detection patterns for common catastrophic backtracking (ReDoS) constructs:
# 1. Nested repetition: (a+)+, (.*)*, (x+)*, ([0-9]+)+
RE_NESTED_QUANTIFIER = re.compile(r"\([^\)]*[\+\*][^\)]*\)[\+\*\{]")
# 2. Alternation with repetition: (a|b+)+, (a+|b+)+
RE_ALTERNATION_NESTED = re.compile(r"\((?:[^|)]*\|)+[^)]*[\+\*]\)[\+\*]")
# 3. Repeated curly braces: (\w{1,}){2,}
RE_NESTED_CURLY = re.compile(r"\{[0-9]+,\}[^\{\}]*\{[0-9]+,\}")


def _detect_redos_risks(pattern: str) -> list[str]:
    """Inspect regex pattern for suspicious backtracking structures."""
    warnings = []
    if RE_NESTED_QUANTIFIER.search(pattern):
        warnings.append("Nested quantifier detected (e.g. '(x+)+' or '(x*)*'); high risk of catastrophic backtracking (ReDoS).")
    if RE_ALTERNATION_NESTED.search(pattern):
        warnings.append("Nested repeating alternation detected (e.g. '(x|y+)+'); high risk of exponential backtracking.")
    if RE_NESTED_CURLY.search(pattern):
        warnings.append("Nested unbounded range quantifier detected (e.g. '{n,}{m,}').")
    return warnings


class RegexExecutionThread(threading.Thread):
    def __init__(self, func, *args, **kwargs):
        super().__init__(daemon=True)
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.result = None
        self.exception = None

    def run(self):
        try:
            self.result = self.func(*self.args, **self.kwargs)
        except Exception as exc:
            self.exception = exc


def _run_with_timeout(func, *args, timeout: float = DEFAULT_TIMEOUT_SEC, **kwargs) -> Any:
    """Execute a regex operation with strict timeout guard."""
    is_main_thread = threading.current_thread() is threading.main_thread()
    can_use_signal = is_main_thread and hasattr(signal, "SIGALRM") and hasattr(signal, "setitimer")

    if can_use_signal:
        old_handler = signal.getsignal(signal.SIGALRM)

        def _alarm_handler(signum, frame):
            raise TimeoutError(f"Regex execution timed out (>{timeout:.1f}s) - potential ReDoS / catastrophic backtracking.")

        try:
            signal.signal(signal.SIGALRM, _alarm_handler)
            signal.setitimer(signal.ITIMER_REAL, timeout)
            return func(*args, **kwargs)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        worker = RegexExecutionThread(func, *args, **kwargs)
        worker.start()
        worker.join(timeout=timeout)
        if worker.is_alive():
            raise TimeoutError(f"Regex execution timed out (>{timeout:.1f}s) - potential ReDoS / catastrophic backtracking.")
        if worker.exception is not None:
            raise worker.exception
        return worker.result


def _parse_flags(flags_arg: Any) -> int:
    """Parse list or string of regex flags into bitwise integer."""
    if not flags_arg:
        return 0
    if isinstance(flags_arg, str):
        flags_list = [f.strip().upper() for f in flags_arg.split("|") if f.strip()]
    elif isinstance(flags_arg, list):
        flags_list = [str(f).strip().upper() for f in flags_arg if f]
    else:
        raise TypeError("Parameter 'flags' must be a list of strings or string.")

    combined = 0
    for flag_name in flags_list:
        if flag_name not in FLAG_MAP:
            raise ValueError(f"Unsupported regex flag: {flag_name!r}. Allowed flags: IGNORECASE, MULTILINE, DOTALL, VERBOSE.")
        combined |= FLAG_MAP[flag_name]
    return combined


def regex_tool(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute regex inspection, matching, search, findall, sub, and ReDoS safety analysis."""
    del context
    try:
        args = arguments or {}
        action = str(args.get("action") or "").strip().lower()
        if not action:
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required 'action' parameter."}

        pattern = args.get("pattern")
        if pattern is None or not isinstance(pattern, str):
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Parameter 'pattern' must be a string."}

        if len(pattern) > MAX_PATTERN_LENGTH:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": f"Pattern exceeds maximum length of {MAX_PATTERN_LENGTH} characters ({len(pattern)} chars).",
            }

        flags_int = _parse_flags(args.get("flags"))

        try:
            compiled = re.compile(pattern, flags_int)
        except re.error as err:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": f"Invalid regular expression: {err}",
            }

        warnings = _detect_redos_risks(pattern)

        if action == "check_pattern":
            payload = {
                "valid": True,
                "is_safe": len(warnings) == 0,
                "warnings": warnings,
                "num_groups": compiled.groups,
                "named_groups": list(compiled.groupindex.keys()),
                "pattern": pattern,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        text = args.get("text", "")
        if not isinstance(text, str):
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Parameter 'text' must be a string."}

        encoded_len = len(text.encode("utf-8"))
        if encoded_len > MAX_TEXT_BYTES:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": f"Input text exceeds maximum limit of {MAX_TEXT_BYTES} bytes ({encoded_len} bytes).",
            }

        limit = max(1, min(int(args.get("limit") if args.get("limit") is not None else 100), MAX_MATCHES_LIMIT))

        if action == "match":
            m = _run_with_timeout(compiled.match, text)
            payload = {
                "matched": m is not None,
                "match": m.group(0) if m else None,
                "span": list(m.span()) if m else None,
                "groups": list(m.groups()) if m else [],
                "groupdict": m.groupdict() if m else {},
                "warnings": warnings,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "search":
            m = _run_with_timeout(compiled.search, text)
            payload = {
                "found": m is not None,
                "match": m.group(0) if m else None,
                "span": list(m.span()) if m else None,
                "groups": list(m.groups()) if m else [],
                "groupdict": m.groupdict() if m else {},
                "warnings": warnings,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action in ("findall", "finditer"):
            def _find():
                found = []
                for match_item in compiled.finditer(text):
                    found.append({
                        "match": match_item.group(0),
                        "span": list(match_item.span()),
                        "groups": list(match_item.groups()),
                        "groupdict": match_item.groupdict(),
                    })
                    if len(found) >= limit:
                        break
                return found

            matches = _run_with_timeout(_find)
            payload = {
                "matches_count": len(matches),
                "matches": matches,
                "limit": limit,
                "truncated": len(matches) >= limit,
                "warnings": warnings,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "sub":
            replacement = args.get("replacement")
            if replacement is None:
                replacement = ""
            elif not isinstance(replacement, str):
                return {"ok": False, "success": False, "data": None, "result": None, "error": "Parameter 'replacement' must be a string."}

            def _sub():
                return compiled.subn(replacement, text, count=limit)

            new_text, sub_count = _run_with_timeout(_sub)
            payload = {
                "new_text": new_text,
                "replacements_count": sub_count,
                "warnings": warnings,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        else:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": f"Unsupported action: {action!r}. Supported actions: match, search, findall, finditer, sub, check_pattern.",
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
    "name": "regex_tool",
    "description": (
        "Pure Python regular expression tool for matching, searching, extracting all occurrences, "
        "substitution, pattern static ReDoS analysis, and execution with a 1.0s timeout guard."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["match", "search", "findall", "finditer", "sub", "check_pattern"],
                "description": "Operation to perform.",
            },
            "pattern": {"type": "string", "description": "Regular expression pattern."},
            "text": {"type": "string", "description": "Target text to evaluate."},
            "replacement": {"type": "string", "description": "Replacement string for action='sub'."},
            "flags": {
                "type": "array",
                "items": {"type": "string", "enum": ["IGNORECASE", "MULTILINE", "DOTALL", "VERBOSE"]},
                "description": "Regex compilation flags.",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 500,
                "description": "Maximum matches or replacements to process (1-500, default: 100).",
            },
        },
        "required": ["action", "pattern"],
        "additionalProperties": False,
    },
    "handler": regex_tool,
    "approval": False,
}
