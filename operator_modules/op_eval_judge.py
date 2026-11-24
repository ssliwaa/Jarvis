"""Zero-dependency Local Evaluation, Lexical Grounding, Hallucination Detection & Red-Teaming Engine.

Synthesizes architectural patterns from:
- Ragas (#17): RAG triad evaluation, proposition splitting, lexical faithfulness & grounding scoring.
- DeepEval (#18): Deterministic assertion testing (contains, regex, json validity, length, grounding).
- Promptfoo (#19): Adversarial prompt injection screening, jailbreak detection, credential exfiltration protection.

Exclusively uses the Python standard library. Zero external dependencies.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

try:
    from atomic_io import atomic_write_text
except ImportError:  # standalone copy: reach the repo root next to operator_modules/
    import sys
    _repo_root = str(Path(__file__).resolve().parents[1])
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)
    from atomic_io import atomic_write_text

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
    "score_faithfulness",
    "score_relevance",
    "check_hallucination",
    "redteam_prompt",
    "assert_test",
    "score_rag_triad",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "context",
    "response",
    "prompt",
    "reference_context",
    "hypothesis",
    "query",
    "input_payload",
    "assertions",
    "threshold",
    "export_path",
})

# Red-teaming threat detection rules
REDTEAM_PATTERNS = [
    (
        "DELIMITER_OVERRIDE",
        "CRITICAL",
        re.compile(
            r"(---+\s*(?:END|START)\s+(?:SYSTEM|PROMPT|INSTRUCTION)|<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|\[INST\])",
            re.IGNORECASE,
        ),
        "Attempted delimiter injection or system instruction frame hijacking.",
    ),
    (
        "JAILBREAK_INSTRUCTION_OVERRIDE",
        "HIGH",
        re.compile(
            r"(ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+(?:all\s+)?prior\s+rules|"
            r"you\s+are\s+now\s+(?:in\s+)?(?:developer\s+mode|unrestricted|DAN|do\s+anything\s+now)|"
            r"hypothetical\s+scenario\s+where\s+(?:rules|ethics|laws)\s+do\s+not\s+apply)",
            re.IGNORECASE,
        ),
        "Instruction override or jailbreak persona attempt detected.",
    ),
    (
        "CREDENTIAL_EXFILTRATION",
        "CRITICAL",
        re.compile(
            r"((?:export|print|cat|echo)\s+[\$A-Za-z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD)|"
            r"/etc/shadow|/etc/passwd|\.ssh/id_rsa|\.aws/credentials|\.env\b)",
            re.IGNORECASE,
        ),
        "Credential or secret exfiltration attempt detected.",
    ),
    (
        "PATH_TRAVERSAL_ESCAPE",
        "HIGH",
        re.compile(r"(\.\./\.\./|\.\.\\\.\.\\|\x00|file:///)", re.IGNORECASE),
        "Filesystem traversal or URI escape sequence detected.",
    ),
    (
        "CODE_EVAL_INJECTION",
        "CRITICAL",
        re.compile(
            r"(__import__\s*\(|eval\s*\(|exec\s*\(|os\.system\s*\(|subprocess\.(?:Popen|run)\s*\()",
            re.IGNORECASE,
        ),
        "Direct code execution or dynamic eval injection detected.",
    ),
]


class EvalError(Exception):
    """Base exception for eval_judge."""


class PathSecurityError(EvalError):
    """Raised when target file resolves outside ALLOWED_ROOTS."""


class SensitivePathError(EvalError):
    """Raised when access to sensitive paths is restricted."""


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


def _extract_text_params(args: dict[str, Any]) -> tuple[str, str, str]:
    """Extract (response/hypothesis, context/reference_context, prompt/query)."""
    response = str(args.get("response") or args.get("hypothesis") or "").strip()
    context = str(args.get("context") or args.get("reference_context") or "").strip()
    prompt = str(args.get("prompt") or args.get("query") or args.get("input_payload") or "").strip()
    return response, context, prompt


def _segment_propositions(text: str) -> list[str]:
    """Segment a block of text into atomic declarative propositions/sentences."""
    raw_sentences = re.split(r"(?<=[.!?])\s+|\n+", text)
    propositions = []
    for s in raw_sentences:
        s_clean = s.strip()
        # Filter out trivial punctuation-only or very short snippets
        if len(s_clean) >= 8 and any(c.isalnum() for c in s_clean):
            propositions.append(s_clean)
    return propositions


def _calculate_grounding(claim: str, context_clean: str) -> float:
    """Compute lexical and semantic alignment of a claim against reference context."""
    words = [w for w in re.findall(r"\w+", claim.casefold()) if len(w) > 3]
    if not words:
        return 1.0

    matched = 0
    for w in words:
        if w in context_clean:
            matched += 1
        elif len(w) > 4 and (
            w.rstrip("s") in context_clean
            or (w + "s") in context_clean
            or w.rstrip("ed") in context_clean
            or w.rstrip("ing") in context_clean
        ):
            matched += 1

    ratio = matched / len(words)
    return round(ratio, 3)


def _score_faithfulness(args: dict[str, Any]) -> dict[str, Any]:
    """Score whether response propositions are factually grounded in reference context."""
    response, context, _ = _extract_text_params(args)
    threshold = float(args.get("threshold") or 0.70)

    if not response:
        raise EvalError("Response or hypothesis is required for score_faithfulness.")
    if not context:
        return {
            "faithfulness_score": 0.0,
            "is_faithful": False,
            "total_claims": 0,
            "grounded_claims": [],
            "ungrounded_claims": [{"claim": response, "grounding_score": 0.0, "reason": "No context provided"}],
        }

    claims = _segment_propositions(response)
    if not claims:
        claims = [response]

    context_clean = context.casefold()
    grounded = []
    ungrounded = []

    for c in claims:
        g_score = _calculate_grounding(c, context_clean)
        claim_info = {"claim": c, "grounding_score": g_score}
        if g_score >= threshold:
            grounded.append(claim_info)
        else:
            ungrounded.append(claim_info)

    faithfulness = round(len(grounded) / max(1, len(claims)), 3)
    is_faithful = faithfulness >= 0.75

    return {
        "faithfulness_score": faithfulness,
        "is_faithful": is_faithful,
        "total_claims": len(claims),
        "grounded_claim_count": len(grounded),
        "ungrounded_claim_count": len(ungrounded),
        "grounded_claims": grounded,
        "ungrounded_claims": ungrounded,
    }


def _score_relevance(args: dict[str, Any]) -> dict[str, Any]:
    """Score whether generated response directly answers the prompt/query."""
    response, _, prompt = _extract_text_params(args)
    if not response or not prompt:
        raise EvalError("Both 'response' and 'prompt' are required for score_relevance.")

    prompt_words = [w for w in re.findall(r"\w+", prompt.casefold()) if len(w) > 3]
    resp_clean = response.casefold()

    if not prompt_words:
        relevance_score = 1.0 if len(response) > 5 else 0.5
        return {
            "relevance_score": relevance_score,
            "is_relevant": relevance_score >= 0.7,
            "matched_keywords": [],
            "rationale": "Prompt contained only short or common words.",
        }

    matched_keywords = [w for w in set(prompt_words) if w in resp_clean]
    keyword_coverage = len(matched_keywords) / len(set(prompt_words))

    # Penalize non-responsive phrases ("I don't know", "Unable to assist", "Sorry", empty)
    evasion_patterns = ["i do not know", "i don't know", "cannot assist", "as an ai", "sorry"]
    evasion_penalty = 0.0
    for ep in evasion_patterns:
        if ep in resp_clean and len(response) < 100:
            evasion_penalty += 0.3

    # Token length balance (penalize extreme brevity)
    length_factor = min(1.0, len(response) / 50.0)

    score = round(max(0.0, min(1.0, 0.7 * keyword_coverage + 0.3 * length_factor - evasion_penalty)), 3)
    is_relevant = score >= 0.65

    return {
        "relevance_score": score,
        "is_relevant": is_relevant,
        "keyword_coverage": round(keyword_coverage, 3),
        "matched_keywords": sorted(matched_keywords),
        "total_prompt_keywords": len(set(prompt_words)),
    }


def _check_hallucination(args: dict[str, Any]) -> dict[str, Any]:
    """Detect hallucinated statements not supported by source context."""
    faith_res = _score_faithfulness(args)
    faithfulness = faith_res["faithfulness_score"]
    hallucination_score = round(1.0 - faithfulness, 3)
    ungrounded = faith_res["ungrounded_claims"]
    has_hallucination = len(ungrounded) > 0 and hallucination_score > 0.25

    return {
        "has_hallucination": has_hallucination,
        "hallucination_score": hallucination_score,
        "faithfulness_score": faithfulness,
        "hallucinated_claims": ungrounded,
        "grounded_claims_count": faith_res["grounded_claim_count"],
        "total_claims_count": faith_res["total_claims"],
    }


def _redteam_prompt(args: dict[str, Any]) -> dict[str, Any]:
    """Scan prompt or tool argument against adversarial injection and jailbreak attacks."""
    _, _, prompt = _extract_text_params(args)
    if not prompt:
        raise EvalError("Prompt or input_payload is required for redteam_prompt.")

    detected_threats = []
    highest_severity = "NONE"
    severity_order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for threat_type, severity, pattern, description in REDTEAM_PATTERNS:
        matches = pattern.findall(prompt)
        if matches:
            if severity_order[severity] > severity_order[highest_severity]:
                highest_severity = severity
            match_strings = [str(m[0] if isinstance(m, tuple) else m)[:100] for m in matches]
            detected_threats.append({
                "threat_type": threat_type,
                "severity": severity,
                "description": description,
                "occurrences": len(matches),
                "matched_samples": match_strings,
            })

    # Generate sanitized output by neutralizing detected threat sequences
    sanitized = prompt
    for _, _, pattern, _ in REDTEAM_PATTERNS:
        sanitized = pattern.sub("[REDACTED_ADVERSARIAL_INPUT]", sanitized)

    is_safe = (len(detected_threats) == 0)

    return {
        "is_safe": is_safe,
        "risk_level": highest_severity,
        "threat_count": len(detected_threats),
        "threats": detected_threats,
        "sanitized_prompt": sanitized,
    }


def _assert_test(args: dict[str, Any]) -> dict[str, Any]:
    """Execute deterministic assertion checks against response content."""
    response, context, _ = _extract_text_params(args)
    assertions = args.get("assertions")
    if not isinstance(assertions, list) or len(assertions) == 0:
        raise EvalError("Parameter 'assertions' must be a non-empty list of assertion dicts.")

    results = []
    all_passed = True

    for idx, item in enumerate(assertions):
        if not isinstance(item, dict):
            continue
        atype = item.get("type")
        val = item.get("value")
        passed = False
        details = ""

        if atype == "contains":
            target = str(val or "")
            passed = target in response
            details = f"Expected substring '{target}' {'found' if passed else 'NOT found'}"
        elif atype == "not_contains":
            target = str(val or "")
            passed = target not in response
            details = f"Forbidden substring '{target}' {'absent' if passed else 'FOUND'}"
        elif atype == "matches_regex":
            pattern = str(val or "")
            try:
                matched = bool(re.search(pattern, response))
                passed = matched
                details = f"Pattern r'{pattern}' {'matched' if passed else 'failed to match'}"
            except re.error as re_err:
                passed = False
                details = f"Invalid regex pattern: {re_err}"
        elif atype == "json_valid":
            try:
                json.loads(response)
                passed = True
                details = "Response parsed as valid JSON"
            except Exception as jerr:
                passed = False
                details = f"Invalid JSON syntax: {jerr}"
        elif atype == "max_length":
            max_len = int(val or 1000)
            passed = len(response) <= max_len
            details = f"Length {len(response)} <= limit {max_len}"
        elif atype == "min_faithfulness":
            threshold = float(val or 0.8)
            fres = _score_faithfulness({"response": response, "context": context, "threshold": threshold})
            score = fres["faithfulness_score"]
            passed = score >= threshold
            details = f"Faithfulness score {score} >= threshold {threshold}"
        else:
            passed = False
            details = f"Unrecognized assertion type '{atype}'"

        if not passed:
            all_passed = False

        results.append({
            "assertion_index": idx,
            "type": atype,
            "expected_value": val,
            "passed": passed,
            "details": details,
        })

    passed_count = sum(1 for r in results if r["passed"])
    return {
        "all_passed": all_passed,
        "passed_count": passed_count,
        "total_count": len(results),
        "pass_rate_pct": round(100.0 * (passed_count / max(1, len(results))), 2),
        "assertion_results": results,
    }


def _score_rag_triad(args: dict[str, Any]) -> dict[str, Any]:
    """Compute the RAG Triad: Faithfulness, Answer Relevance, and Context Precision."""
    faith_res = _score_faithfulness(args)
    rel_res = _score_relevance(args)

    response, context, _ = _extract_text_params(args)
    # Context precision: ratio of context sentences used in grounded claims
    context_sentences = _segment_propositions(context)
    if not context_sentences:
        context_precision = 1.0
    else:
        used_sentences = 0
        resp_cf = response.casefold()
        for cs in context_sentences:
            words = [w for w in re.findall(r"\w+", cs.casefold()) if len(w) > 3]
            if words and sum(1 for w in words if w in resp_cf) / len(words) >= 0.5:
                used_sentences += 1
        context_precision = round(used_sentences / max(1, len(context_sentences)), 3)

    faithfulness = faith_res["faithfulness_score"]
    relevance = rel_res["relevance_score"]
    triad_score = round((faithfulness + relevance + context_precision) / 3.0, 3)

    return {
        "triad_score": triad_score,
        "faithfulness": faithfulness,
        "answer_relevance": relevance,
        "context_precision": context_precision,
        "is_acceptable": triad_score >= 0.70,
        "faithfulness_details": faith_res,
        "relevance_details": rel_res,
    }


def eval_judge(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Main dispatch handler for eval_judge operator tool."""
    if not isinstance(arguments, dict):
        return _envelope_error("Arguments must be a JSON dictionary.")

    extra_keys = set(arguments.keys()) - KNOWN_ARGUMENTS
    if extra_keys:
        return _envelope_error(f"Disallowed additional arguments: {sorted(extra_keys)}")

    action = arguments.get("action")
    if not action or action not in VALID_ACTIONS:
        return _envelope_error(
            f"Invalid or missing action '{action}'. Valid actions: {sorted(VALID_ACTIONS)}"
        )

    try:
        if action == "score_faithfulness":
            res = _score_faithfulness(arguments)
        elif action == "score_relevance":
            res = _score_relevance(arguments)
        elif action == "check_hallucination":
            res = _check_hallucination(arguments)
        elif action == "redteam_prompt":
            res = _redteam_prompt(arguments)
        elif action == "assert_test":
            res = _assert_test(arguments)
        elif action == "score_rag_triad":
            res = _score_rag_triad(arguments)
        else:
            return _envelope_error(f"Unhandled action '{action}'.")

        export_path = arguments.get("export_path")
        if export_path:
            resolved = _validate_path(export_path)
            resolved.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(resolved, json.dumps(res, indent=2), dir_mode=None)
            res["exported_to"] = str(resolved)

        return _envelope_success(res)
    except EvalError as ee:
        return _envelope_error(ee)
    except (ValueError, TypeError) as err:
        return _envelope_error(err)
    except Exception as exc:
        return _envelope_error(exc)


TOOL = {
    "name": "eval_judge",
    "description": (
        "Zero-dependency local LLM evaluation, lexical grounding, hallucination scoring, "
        "deterministic assertion testing, and adversarial prompt red-teaming engine."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "score_faithfulness",
                    "score_relevance",
                    "check_hallucination",
                    "redteam_prompt",
                    "assert_test",
                    "score_rag_triad",
                ],
                "description": "Evaluation action to execute.",
            },
            "context": {
                "type": "string",
                "description": "Ground truth context or source document chunks.",
            },
            "response": {
                "type": "string",
                "description": "Model output or candidate answer to evaluate.",
            },
            "prompt": {
                "type": "string",
                "description": "User question or prompt for relevance/red-teaming evaluation.",
            },
            "reference_context": {
                "type": "string",
                "description": "Alias for context.",
            },
            "hypothesis": {
                "type": "string",
                "description": "Alias for response.",
            },
            "query": {
                "type": "string",
                "description": "Alias for prompt.",
            },
            "input_payload": {
                "type": "string",
                "description": "Raw prompt or argument to test for security vulnerabilities.",
            },
            "assertions": {
                "type": "array",
                "items": {"type": "object"},
                "description": "List of assertion objects for assert_test action.",
            },
            "threshold": {
                "type": "number",
                "description": "Pass/fail numeric score threshold (e.g. 0.75).",
            },
            "export_path": {
                "type": "string",
                "description": "Optional file path within ALLOWED_ROOTS to export evaluation report.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": eval_judge,
    "approval": False,
}
