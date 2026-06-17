"""access_review_automation skill.

Recommends a per-grant decision for an access-certification campaign: one of
``certify`` / ``revoke`` / ``escalate`` / ``manual_review``.

Safety contract: the Go workflow engine maps anything other than a confident
``certify`` to a human escalation, and never auto-revokes from this signal. So
the deterministic baseline is intentionally conservative — it only recommends
``certify`` for clearly low-risk, actively-used grants, and recommends
``escalate`` for stale or unknown ones.
"""
from __future__ import annotations

import logging
from typing import Any

from .errors import SkillError
from .llm import LLMUnavailable, call_llm, parse_json_response

logger = logging.getLogger(__name__)

ALLOWED_DECISIONS = ("certify", "revoke", "escalate", "manual_review")

PRIVILEGED_ROLE_TOKENS = ("admin", "owner", "root", "superuser")
# A grant unused for longer than this is considered stale.
STALE_LAST_USED_DAYS = 90


def _deterministic(payload: dict[str, Any]) -> tuple[str, str]:
    role = str(payload.get("role", "") or "").lower()
    last_used = payload.get("last_used_days")
    usage_events = payload.get("usage_event_count")
    risk_factors = [str(f).lower() for f in payload.get("risk_factors", []) or []]

    if any(tok in role for tok in PRIVILEGED_ROLE_TOKENS):
        return "escalate", f"privileged role {role!r} requires human certification"
    if any("sensitive" in f or "elevated" in f for f in risk_factors):
        return "escalate", "grant carries elevated/sensitive risk factors"

    # bool is a subclass of int, so reject bools explicitly: a JSON true/false
    # must not be read as a usage count of 1/0 and drive a certify decision.
    if isinstance(last_used, int) and not isinstance(last_used, bool):
        if last_used > STALE_LAST_USED_DAYS:
            return "escalate", f"stale grant: unused for {last_used} days"
        if (
            isinstance(usage_events, int)
            and not isinstance(usage_events, bool)
            and usage_events > 0
            and last_used <= 30
        ):
            return "certify", f"actively used (last {last_used}d, {usage_events} events), low-risk role"

    # Unknown usage signals → defer to a human rather than guessing.
    return "manual_review", "insufficient usage signal for an automated decision"


def _llm_enrich(payload: dict[str, Any]) -> tuple[str, str] | None:
    prompt = (
        "You assist an access-certification campaign. Given the grant JSON, respond ONLY with "
        '{"decision": "certify|revoke|escalate|manual_review", "reason": "..."}. '
        "Only certify clearly safe, actively-used, non-privileged grants. When in doubt, escalate.\n"
        f"Grant: {payload}"
    )
    try:
        raw = call_llm(prompt, system="Return strict JSON. Never certify privileged or stale access.")
        parsed = parse_json_response(raw)
    except LLMUnavailable:
        return None
    decision = str(parsed.get("decision", "")).strip().lower()
    if decision not in ALLOWED_DECISIONS:
        return None
    return decision, str(parsed.get("reason", "") or "llm review recommendation")


def run(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SkillError("payload must be an object")
    if not payload.get("resource_ref"):
        raise SkillError("resource_ref is required")

    decision, reason = _deterministic(payload)
    enriched = _llm_enrich(payload)
    if enriched is not None:
        llm_decision, llm_reason = enriched
        # The model may escalate a deterministic certify, but a deterministic
        # escalate/manual is never downgraded to certify by the model.
        if decision == "certify" and llm_decision != "certify":
            decision, reason = llm_decision, f"llm overrode certify → {llm_decision}: {llm_reason}"
        elif decision == "certify" and llm_decision == "certify":
            reason = f"rules+llm agree certify: {llm_reason}"

    return {"decision": decision, "reason": reason}
