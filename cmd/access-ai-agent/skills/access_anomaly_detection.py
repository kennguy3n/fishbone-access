"""access_anomaly_detection skill.

Surfaces behavioural anomalies for an access grant. Output is a list of anomaly
objects ``{kind, reason, severity, confidence}``. Detection is advisory: the Go
side never blocks a decision on it, so an empty list (no anomalies) is a valid,
common response.
"""
from __future__ import annotations

import logging
from typing import Any

from .errors import SkillError
from .llm import LLMUnavailable, call_llm, parse_json_response

logger = logging.getLogger(__name__)

ALLOWED_SEVERITIES = ("low", "medium", "high")

# Hours outside this inclusive window are considered off-hours (local time).
BUSINESS_HOURS = range(7, 20)
# More than this many distinct source regions is suspicious (impossible travel).
MAX_NORMAL_REGIONS = 2
STALE_LAST_USED_DAYS = 90


def _deterministic(payload: dict[str, Any]) -> list[dict[str, Any]]:
    anomalies: list[dict[str, Any]] = []

    regions = [str(r) for r in payload.get("usage_regions", []) or []]
    distinct_regions = sorted(set(regions))
    if len(distinct_regions) > MAX_NORMAL_REGIONS:
        anomalies.append({
            "kind": "multi_region_access",
            "reason": f"access from {len(distinct_regions)} regions: {', '.join(distinct_regions)}",
            "severity": "high",
            "confidence": 0.8,
        })

    hours = [h for h in payload.get("usage_hours", []) or [] if isinstance(h, int)]
    off_hours = sorted({h for h in hours if h not in BUSINESS_HOURS})
    if off_hours:
        anomalies.append({
            "kind": "off_hours_access",
            "reason": f"access during off-hours: {off_hours}",
            "severity": "medium",
            "confidence": 0.6,
        })

    last_used = payload.get("last_used_days")
    if isinstance(last_used, int) and last_used > STALE_LAST_USED_DAYS:
        anomalies.append({
            "kind": "dormant_grant_reactivation",
            "reason": f"grant unused for {last_used} days",
            "severity": "medium",
            "confidence": 0.5,
        })

    return anomalies


def _normalize(items: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(items, list):
        return out
    for it in items:
        if not isinstance(it, dict) or not it.get("kind"):
            continue
        severity = str(it.get("severity", "medium")).strip().lower()
        if severity not in ALLOWED_SEVERITIES:
            severity = "medium"
        confidence = it.get("confidence", 0.5)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = min(1.0, max(0.0, confidence))
        out.append({
            "kind": str(it["kind"]),
            "reason": str(it.get("reason", "")),
            "severity": severity,
            "confidence": confidence,
        })
    return out


def _llm_enrich(payload: dict[str, Any]) -> list[dict[str, Any]] | None:
    prompt = (
        "You detect access anomalies. Given the grant-usage JSON, respond ONLY with "
        '{"anomalies": [{"kind": "...", "reason": "...", "severity": "low|medium|high", '
        '"confidence": 0.0}]}. Return an empty list when nothing is anomalous.\n'
        f"Usage: {payload}"
    )
    try:
        raw = call_llm(prompt, system="Return strict JSON. Do not invent anomalies without evidence.")
        parsed = parse_json_response(raw)
    except LLMUnavailable:
        return None
    return _normalize(parsed.get("anomalies"))


def run(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SkillError("payload must be an object")
    if not payload.get("grant_id"):
        raise SkillError("grant_id is required")

    anomalies = _deterministic(payload)
    llm_anomalies = _llm_enrich(payload)
    if llm_anomalies:
        seen = {a["kind"] for a in anomalies}
        for a in llm_anomalies:
            if a["kind"] not in seen:
                anomalies.append(a)
                seen.add(a["kind"])

    return {"anomalies": anomalies}
