"""pam_behavioural_analytics skill.

Surfaces behavioural anomalies for a privileged user's recent PAM sessions by
comparing them against a (optional) baseline of the user's normal behaviour.
Output is a list of anomaly objects ``{kind, reason, severity, confidence}`` —
the same envelope as access_anomaly_detection — so the Go side reuses the
anomaly fallback path. Detection is advisory decision-support: this agent never
proxies or gates the session itself (that is the PAM layer), and an
empty list (nothing anomalous) is a valid, common response.
"""
from __future__ import annotations

import logging
from typing import Any

from .errors import SkillError
from .llm import LLMUnavailable, call_llm, parse_json_response
from .numeric import as_hour, as_number

logger = logging.getLogger(__name__)

ALLOWED_SEVERITIES = ("low", "medium", "high")

# Business hours are 07:00-19:59 local time (hours 7 through 19); a session
# starting outside this window is treated as off-hours.
BUSINESS_HOURS = range(7, 20)
# A session command count this many times the baseline average is a volume spike.
VOLUME_SPIKE_FACTOR = 3.0
# Absolute floor so a tiny baseline (avg 1-2 cmds) does not trip on small bursts.
VOLUME_SPIKE_MIN_COMMANDS = 30


def _sessions(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in payload.get("sessions", []) or [] if isinstance(s, dict)]


def _deterministic(payload: dict[str, Any]) -> list[dict[str, Any]]:
    anomalies: list[dict[str, Any]] = []
    sessions = _sessions(payload)
    baseline_raw = payload.get("baseline")
    baseline: dict[str, Any] = baseline_raw if isinstance(baseline_raw, dict) else {}

    # Off-hours sessions: any session whose start hour is outside business hours.
    # as_hour accepts an int or its integral-float JSON equivalent (3 or 3.0)
    # and rejects bools (a subclass of int) and fractional hours, so a JSON
    # true/false start_hour is never read as the hour 1/0.
    start_hours = (as_hour(s.get("start_hour")) for s in sessions)
    off_hours = sorted({h for h in start_hours if h is not None and h not in BUSINESS_HOURS})
    if off_hours:
        anomalies.append({
            "kind": "off_hours_sessions",
            "reason": f"privileged sessions started during off-hours: {off_hours}",
            "severity": "medium",
            "confidence": 0.6,
        })

    # New targets: sessions touching targets not present in the baseline set.
    known_targets = {str(t) for t in baseline.get("targets", []) or []}
    if known_targets:
        seen_targets = {str(s["target"]) for s in sessions if s.get("target")}
        novel = sorted(seen_targets - known_targets)
        if novel:
            anomalies.append({
                "kind": "new_target_access",
                "reason": f"access to targets outside baseline: {', '.join(novel)}",
                "severity": "high",
                "confidence": 0.7,
            })

    # Volume spike: a session whose command count dwarfs the baseline average.
    # Both the baseline average and the per-session count accept int or float
    # (as_number) and reject bools; the raw counts are kept for the reason so
    # integers render without a trailing ".0".
    avg_raw = baseline.get("avg_command_count")
    avg_commands = as_number(avg_raw)
    if avg_commands is not None and avg_commands > 0:
        threshold = max(avg_commands * VOLUME_SPIKE_FACTOR, VOLUME_SPIKE_MIN_COMMANDS)
        # Keep the raw counts (int or float) for display; as_number only gates
        # which sessions qualify, so an integer count renders without a ".0".
        spikes: list[Any] = []
        for s in sessions:
            raw_count = s.get("command_count")
            count = as_number(raw_count)
            if count is not None and count > threshold:
                spikes.append(raw_count)
        if spikes:
            anomalies.append({
                "kind": "command_volume_spike",
                "reason": f"session command volume {max(spikes)} far exceeds baseline avg {avg_raw}",
                "severity": "medium",
                "confidence": 0.6,
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
        "You analyse privileged-user session behaviour for anomalies versus a baseline. "
        'Given the JSON, respond ONLY with {"anomalies": [{"kind": "...", "reason": "...", '
        '"severity": "low|medium|high", "confidence": 0.0}]}. Return an empty list when '
        "behaviour is consistent with the baseline.\n"
        f"Behaviour: {payload}"
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
    if not payload.get("user_external_id"):
        raise SkillError("user_external_id is required")

    anomalies = _deterministic(payload)
    llm_anomalies = _llm_enrich(payload)
    if llm_anomalies:
        seen = {a["kind"] for a in anomalies}
        for a in llm_anomalies:
            if a["kind"] not in seen:
                anomalies.append(a)
                seen.add(a["kind"])

    return {"anomalies": anomalies}
