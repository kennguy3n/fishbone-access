"""pam_session_risk_assessment skill.

Scores a privileged session (user + target + the commands they ran) on a
low / medium / high scale with a recommendation string. This is a
decision-support signal consumed by the PAM layer; this agent only
produces the score — it does not proxy or gate the session itself.

The Go side wraps it with AssessSessionRiskWithFallback, so a failure defaults
to "medium" (manual review advised).
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any

from .errors import SkillError
from .llm import LLMUnavailable, call_llm, parse_json_response

logger = logging.getLogger(__name__)

ALLOWED_SCORES = ("low", "medium", "high")
_ORDER = {"low": 0, "medium": 1, "high": 2}

# Command substrings that indicate destructive or high-impact operations.
DANGEROUS_COMMAND_TOKENS = (
    "rm -rf", "drop table", "drop database", "truncate", "shutdown", "reboot",
    "mkfs", "dd if=", "chmod 777", "chown -r", "iptables -f", "passwd",
    "useradd", "userdel", "visudo", "curl ", "wget ", "base64 -d",
)
# Tokens that read/exfiltrate credentials.
CREDENTIAL_COMMAND_TOKENS = ("cat /etc/shadow", "id_rsa", ".aws/credentials", "kubeconfig", "secret")


def _max_score(a: str, b: str) -> str:
    return a if _ORDER[a] >= _ORDER[b] else b


def _is_external_ip(raw: str) -> bool:
    """True when ``raw`` is a routable public address. RFC 1918 / loopback /
    link-local / unique-local addresses are internal. An unparseable value is
    treated as external (fail-safe: surface it for review rather than silently
    trusting an opaque source)."""
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return True
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def _deterministic(payload: dict[str, Any]) -> tuple[str, list[str], str]:
    commands = [str(c).lower() for c in payload.get("commands", []) or []]
    factors: list[str] = []
    score = "low"

    dangerous = [c for c in commands if any(tok in c for tok in DANGEROUS_COMMAND_TOKENS)]
    if dangerous:
        factors.append(f"dangerous_commands:{len(dangerous)}")
        score = "high"

    credentialed = [c for c in commands if any(tok in c for tok in CREDENTIAL_COMMAND_TOKENS)]
    if credentialed:
        factors.append(f"credential_access:{len(credentialed)}")
        score = "high"

    if len(commands) > 50:
        factors.append(f"high_command_volume:{len(commands)}")
        score = _max_score(score, "medium")

    source_ip = str(payload.get("source_ip", "") or "").strip()
    if source_ip and _is_external_ip(source_ip):
        factors.append(f"external_source_ip:{source_ip}")
        score = _max_score(score, "medium")

    if not factors:
        factors.append("baseline_low_risk")
    recommendation = {
        "high": "terminate or require step-up MFA; review session transcript",
        "medium": "flag for human review",
        "low": "allow; routine privileged session",
    }[score]
    return score, factors, recommendation


def _llm_enrich(payload: dict[str, Any], floor: str) -> tuple[str, list[str], str] | None:
    prompt = (
        "You score privileged-session risk. Given the session JSON, respond ONLY with "
        '{"risk_score": "low|medium|high", "risk_factors": ["..."], "recommendation": "..."}.\n'
        f"Session: {payload}"
    )
    try:
        raw = call_llm(prompt, system="Return strict JSON. Destructive or credential-reading commands are high risk.")
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
    recommendation = str(parsed.get("recommendation", "") or "review session")
    return score, factors, recommendation


def run(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SkillError("payload must be an object")
    if not payload.get("user_external_id"):
        raise SkillError("user_external_id is required")
    if not payload.get("target_ref"):
        raise SkillError("target_ref is required")

    score, factors, recommendation = _deterministic(payload)
    enriched = _llm_enrich(payload, floor=score)
    if enriched is not None:
        score, llm_factors, recommendation = enriched
        for f in llm_factors:
            if f not in factors:
                factors.append(f)

    return {"risk_score": score, "risk_factors": factors, "recommendation": recommendation}
