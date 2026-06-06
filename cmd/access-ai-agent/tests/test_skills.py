"""Unit tests for each skill: deterministic baseline, LLM enrichment, and the
fail-safe fallback when the LLM is unavailable."""
from __future__ import annotations

import json

import pytest

from skills import (
    access_anomaly_detection,
    access_review_automation,
    access_risk_assessment,
    connector_setup_assistant,
    llm,
    pam_session_risk_assessment,
    policy_recommendation,
)
from skills.errors import SkillError


@pytest.fixture(autouse=True)
def _no_real_llm(monkeypatch):
    # Ensure no skill accidentally reaches a network: default provider unset.
    monkeypatch.delenv(llm.ENV_PROVIDER, raising=False)
    yield


# --------------------------- access_risk_assessment ---------------------------

def test_risk_requires_role_and_resource():
    with pytest.raises(SkillError):
        access_risk_assessment.run({"resource_external_id": "r1"})
    with pytest.raises(SkillError):
        access_risk_assessment.run({"role": "viewer"})


def test_risk_privileged_role_is_high():
    out = access_risk_assessment.run({"role": "admin", "resource_external_id": "db-1"})
    assert out["risk_score"] == "high"
    assert any("privileged_role" in f for f in out["risk_factors"])


def test_risk_readonly_baseline_low():
    out = access_risk_assessment.run(
        {"role": "viewer", "resource_external_id": "wiki", "justification": "on-call"}
    )
    assert out["risk_score"] == "low"


def test_risk_production_tag_bumps():
    out = access_risk_assessment.run(
        {"role": "editor", "resource_external_id": "svc", "resource_tags": ["prod"], "justification": "x"}
    )
    assert out["risk_score"] in ("medium", "high")


def test_risk_llm_can_raise_not_lower(monkeypatch):
    # Deterministic floor is "low"; the model says "high" → result is "high".
    token = llm.set_test_provider(lambda p, s: json.dumps({"risk_score": "high", "risk_factors": ["model"]}))
    try:
        out = access_risk_assessment.run(
            {"role": "viewer", "resource_external_id": "wiki", "justification": "x"}
        )
    finally:
        llm.reset_test_provider(token)
    assert out["risk_score"] == "high"
    assert "llm_assessed" in out["risk_factors"]


def test_risk_llm_cannot_lower_below_floor(monkeypatch):
    # Deterministic floor is "high" (admin); model "low" must NOT lower it.
    token = llm.set_test_provider(lambda p, s: json.dumps({"risk_score": "low", "risk_factors": []}))
    try:
        out = access_risk_assessment.run({"role": "admin", "resource_external_id": "db"})
    finally:
        llm.reset_test_provider(token)
    assert out["risk_score"] == "high"


# -------------------------- access_review_automation --------------------------

def test_review_requires_resource_ref():
    with pytest.raises(SkillError):
        access_review_automation.run({})


def test_review_privileged_escalates():
    out = access_review_automation.run({"resource_ref": "x", "role": "admin"})
    assert out["decision"] == "escalate"


def test_review_active_low_risk_certifies():
    out = access_review_automation.run(
        {"resource_ref": "x", "role": "viewer", "last_used_days": 3, "usage_event_count": 42}
    )
    assert out["decision"] == "certify"


def test_review_stale_escalates():
    out = access_review_automation.run(
        {"resource_ref": "x", "role": "viewer", "last_used_days": 200, "usage_event_count": 1}
    )
    assert out["decision"] == "escalate"


def test_review_unknown_usage_is_manual():
    out = access_review_automation.run({"resource_ref": "x", "role": "viewer"})
    assert out["decision"] == "manual_review"


def test_review_llm_cannot_downgrade_to_certify(monkeypatch):
    # Deterministic says escalate (stale); model says certify → stays escalate.
    token = llm.set_test_provider(lambda p, s: json.dumps({"decision": "certify", "reason": "lgtm"}))
    try:
        out = access_review_automation.run(
            {"resource_ref": "x", "role": "viewer", "last_used_days": 300}
        )
    finally:
        llm.reset_test_provider(token)
    assert out["decision"] == "escalate"


# -------------------------- access_anomaly_detection --------------------------

def test_anomaly_requires_grant_id():
    with pytest.raises(SkillError):
        access_anomaly_detection.run({})


def test_anomaly_multi_region_high():
    out = access_anomaly_detection.run(
        {"grant_id": "g1", "usage_regions": ["us", "eu", "apac"]}
    )
    kinds = {a["kind"] for a in out["anomalies"]}
    assert "multi_region_access" in kinds


def test_anomaly_none_is_empty():
    out = access_anomaly_detection.run(
        {"grant_id": "g1", "usage_regions": ["us"], "usage_hours": [9, 10, 14]}
    )
    assert out["anomalies"] == []


def test_anomaly_off_hours_detected():
    out = access_anomaly_detection.run({"grant_id": "g1", "usage_hours": [2, 3]})
    kinds = {a["kind"] for a in out["anomalies"]}
    assert "off_hours_access" in kinds


# ------------------------ pam_session_risk_assessment ------------------------

def test_pam_requires_user_and_target():
    with pytest.raises(SkillError):
        pam_session_risk_assessment.run({"user_external_id": "u"})
    with pytest.raises(SkillError):
        pam_session_risk_assessment.run({"target_ref": "t"})


def test_pam_dangerous_command_high():
    out = pam_session_risk_assessment.run(
        {"user_external_id": "u", "target_ref": "host", "commands": ["sudo rm -rf /var"]}
    )
    assert out["risk_score"] == "high"
    assert out["recommendation"]


def test_pam_routine_low():
    out = pam_session_risk_assessment.run(
        {"user_external_id": "u", "target_ref": "host", "commands": ["ls", "cat config.yaml"], "source_ip": "10.0.0.5"}
    )
    assert out["risk_score"] == "low"


# --------------------------- policy_recommendation ---------------------------

def test_policy_requires_workspace_id():
    with pytest.raises(SkillError):
        policy_recommendation.run({})


def test_policy_broad_role_flagged():
    out = policy_recommendation.run({"workspace_id": "w1", "resource": "db", "roles": ["admin"]})
    assert "least-privilege" in out["explanation"].lower() or "broad" in out["explanation"].lower()


def test_policy_llm_used_when_available():
    token = llm.set_test_provider(lambda p, s: "Grant a scoped reader role, time-boxed to 8h.")
    try:
        out = policy_recommendation.run({"workspace_id": "w1", "resource": "db", "roles": ["reader"]})
    finally:
        llm.reset_test_provider(token)
    assert "time-boxed" in out["explanation"]


# -------------------------- connector_setup_assistant -------------------------

def test_connector_requires_provider():
    with pytest.raises(SkillError):
        connector_setup_assistant.run({})


@pytest.mark.parametrize(
    ("provider", "strategy"),
    [
        ("okta", "oidc"),
        ("Entra", "microsoft"),
        ("google_workspace", "google-oauth2"),
        ("zoho", "zoho"),
        ("github", "github"),
    ],
)
def test_connector_strategy_mapping(provider, strategy):
    out = connector_setup_assistant.run({"provider": provider})
    assert out["reason"] == f"strategy={strategy}"


def test_connector_unknown_provider_explains():
    out = connector_setup_assistant.run({"provider": "totally-unknown"})
    assert out["reason"] == "strategy=unknown"
    assert "no known iam-core strategy" in out["explanation"]
