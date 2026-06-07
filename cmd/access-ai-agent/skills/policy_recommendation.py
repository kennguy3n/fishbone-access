"""policy_recommendation skill.

Produces a human-readable explanation / recommendation for an access policy
question (e.g. "what roles should this resource grant?"). Advisory only — the Go
side returns an empty string on failure and never blocks on it.
"""
from __future__ import annotations

import logging
from typing import Any

from .errors import SkillError
from .llm import LLMUnavailable, call_llm

logger = logging.getLogger(__name__)

# Roles considered broad/over-privileged when requested without scoping.
BROAD_ROLES = {"admin", "owner", "root", "superuser", "*", "all"}


def _deterministic(payload: dict[str, Any]) -> str:
    resource = str(payload.get("resource", "") or "").strip()
    roles = [str(r) for r in payload.get("roles", []) or []]
    context = str(payload.get("context", "") or "").strip()

    parts: list[str] = []
    target = resource or "the requested resource"
    broad = [r for r in roles if r.lower() in BROAD_ROLES]
    if broad:
        parts.append(
            f"Requested role(s) {broad} on {target} are broad. Prefer least-privilege: "
            "grant a narrowly-scoped role and time-box the access."
        )
    elif roles:
        parts.append(f"Roles {roles} on {target} appear scoped; confirm they match the stated need.")
    else:
        parts.append(f"No roles specified for {target}; enumerate the minimal role set before granting.")

    parts.append("Require an approval chain for any production or sensitive resource and set an expiry.")
    if context:
        parts.append(f"Context considered: {context}.")
    return " ".join(parts)


def _llm_enrich(payload: dict[str, Any]) -> str | None:
    prompt = (
        "You are a least-privilege access-policy advisor. Given the JSON, write 2-4 sentences "
        "recommending the minimal roles, approval requirements, and expiry. Plain text, no JSON.\n"
        f"Request: {payload}"
    )
    try:
        text = call_llm(prompt, system="Be concise and concrete. Favour least privilege and time-boxed access.")
    except LLMUnavailable:
        return None
    text = text.strip()
    return text or None


def run(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SkillError("payload must be an object")
    if not payload.get("workspace_id"):
        raise SkillError("workspace_id is required")

    explanation = _llm_enrich(payload) or _deterministic(payload)
    return {"explanation": explanation}
