"""access_risk_assessment skill.

Scores an access request on a low / medium / high scale plus a structured
risk_factors list. The Go side wraps every call with AssessRiskWithFallback so
a failure here defaults to risk_score="medium" (→ manager_approval).

Deterministic scoring is the baseline; when a local LLM is configured the score
is enriched (never lowered below the deterministic floor — the model can raise
concern but cannot rubber-stamp a privileged request down to "low").
"""
from __future__ import annotations

import logging
from typing import Any

from .errors import SkillError
from .llm import LLMUnavailable, call_llm, parse_json_response

logger = logging.getLogger(__name__)

# Roles the platform treats as privileged: any of these forces "high".
PRIVILEGED_ROLES = {"admin", "owner", "root", "superuser", "domain_admin"}
# Substrings that indicate a write-capable (non-read-only) role → at least medium.
WRITE_ROLE_TOKENS = ("write", "edit", "admin", "modify", "delete", "deploy")
# Tags indicating a production / sensitive resource → bump one band.
ELEVATED_TAGS = {"prod", "production", "prd", "tier:1", "sensitive", "pii", "regulated"}

ALLOWED_SCORES = ("low", "medium", "high")
_ORDER = {"low": 0, "medium": 1, "high": 2}


def _max_score(a: str, b: str) -> str:
    return a if _ORDER[a] >= _ORDER[b] else b


def _deterministic(payload: dict[str, Any]) -> tuple[str, list[str]]:
    role = str(payload["role"])
    lowered = role.lower()
    tags = {str(t).lower() for t in payload.get("resource_tags", []) or []}
    factors: list[str] = []
    score = "low"

    if lowered in PRIVILEGED_ROLES:
        factors.append(f"privileged_role:{lowered}")
        score = "high"
    elif any(tok in lowered for tok in WRITE_ROLE_TOKENS):
        factors.append(f"write_role:{lowered}")
        score = _max_score(score, "medium")

    elevated = tags & ELEVATED_TAGS
    if elevated:
        factors.append("elevated_resource:" + ",".join(sorted(elevated)))
        # Bump the score up one band for an elevated resource tag: low→medium,
        # medium→high, high→high (already capped). The ternary picks the next
        # band's floor and _max_score keeps the higher of the two.
        score = _max_score(score, "high" if score != "low" else "medium")

    duration = payload.get("duration_hours")
    if isinstance(duration, int) and duration > 168:  # standing access (> 1 week)
        factors.append(f"long_duration_hours:{duration}")
        score = _max_score(score, "medium")

    justification = str(payload.get("justification", "") or "").strip()
    if not justification:
        factors.append("missing_justification")
        score = _max_score(score, "medium")

    if not factors:
        factors.append("baseline_low_risk")
    return score, factors


def _llm_enrich(payload: dict[str, Any], floor: str) -> tuple[str, list[str]] | None:
    """Ask the local model to assess risk. Returns None when the LLM is
    unavailable or its answer is unusable; never lowers below ``floor``."""
    prompt = (
        "You are an access-governance risk scorer. Given the access request JSON, "
        'respond ONLY with a JSON object {"risk_score": "low|medium|high", '
        '"risk_factors": ["..."], "reason": "..."}.\n'
        f"Request: {payload}"
    )
    try:
        raw = call_llm(prompt, system="Return strict JSON. Be conservative; privileged or production access is high risk.")
        parsed = parse_json_response(raw)
    except LLMUnavailable:
        return None
    score = str(parsed.get("risk_score", "")).strip().lower()
    if score not in ALLOWED_SCORES:
        return None
    score = _max_score(score, floor)
    raw_factors = parsed.get("risk_factors", [])
    factors = [str(f) for f in raw_factors] if isinstance(raw_factors, list) else []
    factors.append("llm_assessed")
    return score, factors


def run(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SkillError("payload must be an object")
    role = payload.get("role")
    resource = payload.get("resource_external_id")
    if not role or not isinstance(role, str):
        raise SkillError("role is required and must be a string")
    if not resource or not isinstance(resource, str):
        raise SkillError("resource_external_id is required and must be a string")

    score, factors = _deterministic(payload)
    enriched = _llm_enrich(payload, floor=score)
    if enriched is not None:
        score, llm_factors = enriched
        # Union the deterministic + model factors, preserving order, de-duped.
        for f in llm_factors:
            if f not in factors:
                factors.append(f)
        reason = f"llm+rules risk={score}"
    else:
        reason = f"rule-based risk={score} from {len(factors)} factor(s)"

    return {"risk_score": score, "risk_factors": factors, "reason": reason}
