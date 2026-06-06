"""Tests for the FastAPI app / dispatcher (no TLS — pure ASGI via TestClient)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv(main.ENV_API_KEY, raising=False)
    return TestClient(main.create_app())


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_readyz_lists_skills(client):
    resp = client.get("/readyz")
    assert resp.status_code == 200
    assert "access_risk_assessment" in resp.json()["skills"]


def test_readyz_unready_on_external_provider(client, monkeypatch):
    monkeypatch.setenv("ACCESS_AI_LLM_PROVIDER", "openai")
    resp = client.get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["status"] == "unready"


def test_invoke_dispatch(client):
    resp = client.post(
        "/a2a/invoke",
        json={"skill_name": "access_risk_assessment", "payload": {"role": "admin", "resource_external_id": "db"}},
    )
    assert resp.status_code == 200
    assert resp.json()["risk_score"] == "high"


def test_invoke_unknown_skill_404(client):
    resp = client.post("/a2a/invoke", json={"skill_name": "does_not_exist", "payload": {}})
    assert resp.status_code == 404


def test_invoke_bad_payload_400(client):
    # Missing required role/resource → SkillError → 400.
    resp = client.post("/a2a/invoke", json={"skill_name": "access_risk_assessment", "payload": {}})
    assert resp.status_code == 400


def test_invoke_requires_skill_name(client):
    resp = client.post("/a2a/invoke", json={"payload": {}})
    assert resp.status_code == 422  # pydantic validation


def test_api_key_enforced(monkeypatch):
    monkeypatch.setenv(main.ENV_API_KEY, "s3cret")
    c = TestClient(main.create_app())
    # No key → 401.
    resp = c.post("/a2a/invoke", json={"skill_name": "access_risk_assessment", "payload": {"role": "x", "resource_external_id": "y"}})
    assert resp.status_code == 401
    # Correct key → 200.
    resp = c.post(
        "/a2a/invoke",
        headers={"X-API-Key": "s3cret"},
        json={"skill_name": "access_risk_assessment", "payload": {"role": "viewer", "resource_external_id": "y", "justification": "x"}},
    )
    assert resp.status_code == 200


def test_workspace_tier_deterministic_skips_llm(client):
    # The dispatcher must wire workspace_ai_tier into the contextvar BEFORE the
    # skill runs. With a test provider that would force "high", tier=deterministic
    # must still short-circuit to the rule-based "low" result.
    from skills import llm

    calls = {"n": 0}

    def _fake(prompt, system):
        calls["n"] += 1
        return '{"risk_score": "high"}'

    token = llm.set_test_provider(_fake)
    try:
        resp = client.post(
            "/a2a/invoke",
            json={
                "skill_name": "access_risk_assessment",
                "payload": {"role": "viewer", "resource_external_id": "y", "justification": "x"},
                "workspace_ai_tier": "deterministic",
            },
        )
    finally:
        llm.reset_test_provider(token)
    assert resp.status_code == 200
    assert resp.json()["risk_score"] == "low"
    assert calls["n"] == 0  # the model was never consulted


def test_workspace_tier_default_uses_llm(client):
    # With no tier pin, the test provider IS consulted and can raise the score.
    from skills import llm

    token = llm.set_test_provider(lambda p, s: '{"risk_score": "high", "risk_factors": ["m"]}')
    try:
        resp = client.post(
            "/a2a/invoke",
            json={
                "skill_name": "access_risk_assessment",
                "payload": {"role": "viewer", "resource_external_id": "y", "justification": "x"},
            },
        )
    finally:
        llm.reset_test_provider(token)
    assert resp.status_code == 200
    assert resp.json()["risk_score"] == "high"
