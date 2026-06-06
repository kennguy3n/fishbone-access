"""Unit tests for the shared LLM client choke point."""
from __future__ import annotations

import pytest

from skills import llm


def test_external_provider_rejected_at_boot(monkeypatch):
    monkeypatch.setenv(llm.ENV_PROVIDER, "openai")
    with pytest.raises(llm.ExternalProviderError):
        llm.assert_provider_allowed()


def test_external_provider_variants_rejected(monkeypatch):
    for provider in ("anthropic", "azure", "bedrock", "vertex", "google", "groq"):
        monkeypatch.setenv(llm.ENV_PROVIDER, provider)
        with pytest.raises(llm.ExternalProviderError):
            llm.assert_provider_allowed()


def test_local_and_unset_providers_allowed_at_boot(monkeypatch):
    for provider in ("", "stub", "deterministic", "local", "local-4b", "local-8b"):
        monkeypatch.setenv(llm.ENV_PROVIDER, provider)
        llm.assert_provider_allowed()  # must not raise


def test_call_llm_unset_provider_raises_unavailable(monkeypatch):
    monkeypatch.delenv(llm.ENV_PROVIDER, raising=False)
    with pytest.raises(llm.LLMUnavailable):
        llm.call_llm("hi")


def test_call_llm_deterministic_tier_short_circuits(monkeypatch):
    monkeypatch.setenv(llm.ENV_PROVIDER, "local")
    monkeypatch.setenv(llm.ENV_BASE_URL, "http://127.0.0.1:9")
    token = llm.set_workspace_ai_tier("deterministic")
    try:
        with pytest.raises(llm.LLMUnavailable):
            llm.call_llm("hi")
    finally:
        llm.reset_workspace_ai_tier(token)


def test_call_llm_external_provider_runtime_raises(monkeypatch):
    monkeypatch.setenv(llm.ENV_PROVIDER, "openai")
    with pytest.raises(llm.ExternalProviderError):
        llm.call_llm("hi")


def test_call_llm_local_without_base_url_raises(monkeypatch):
    monkeypatch.setenv(llm.ENV_PROVIDER, "local")
    monkeypatch.delenv(llm.ENV_BASE_URL, raising=False)
    with pytest.raises(llm.LLMUnavailable):
        llm.call_llm("hi")


def test_test_provider_seam(monkeypatch):
    token = llm.set_test_provider(lambda prompt, system: "from-test")
    try:
        assert llm.call_llm("ignored") == "from-test"
    finally:
        llm.reset_test_provider(token)


def test_parse_json_response_plain():
    assert llm.parse_json_response('{"a": 1}') == {"a": 1}


def test_parse_json_response_fenced():
    assert llm.parse_json_response('```json\n{"a": 2}\n```') == {"a": 2}


def test_parse_json_response_non_object_raises():
    with pytest.raises(llm.LLMUnavailable):
        llm.parse_json_response("[1, 2, 3]")


def test_parse_json_response_garbage_raises():
    with pytest.raises(llm.LLMUnavailable):
        llm.parse_json_response("not json at all")


def test_resolve_model_by_tier(monkeypatch):
    monkeypatch.setenv(llm.ENV_MODEL, "default-model")
    monkeypatch.setenv(llm.ENV_MODEL_4B, "model-4b")
    monkeypatch.setenv(llm.ENV_MODEL_8B, "model-8b")

    token = llm.set_workspace_ai_tier("local_8b")
    try:
        assert llm._resolve_model() == "model-8b"
    finally:
        llm.reset_workspace_ai_tier(token)

    token = llm.set_workspace_ai_tier("local_4b")
    try:
        assert llm._resolve_model() == "model-4b"
    finally:
        llm.reset_workspace_ai_tier(token)

    token = llm.set_workspace_ai_tier("")
    try:
        assert llm._resolve_model() == "default-model"
    finally:
        llm.reset_workspace_ai_tier(token)
