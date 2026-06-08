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


def test_parse_json_response_recovers_object_from_prose():
    # Smaller local models often wrap the object in a preamble/trailer.
    text = 'Here is the assessment:\n{"risk": "high", "score": 0.9}\nHope this helps!'
    assert llm.parse_json_response(text) == {"risk": "high", "score": 0.9}


def test_parse_json_response_ignores_braces_in_strings():
    text = 'noise {"note": "a } brace in a string", "ok": true} trailing'
    assert llm.parse_json_response(text) == {
        "note": "a } brace in a string",
        "ok": True,
    }


def test_parse_json_response_skips_malformed_then_finds_valid():
    # A malformed leading {...} is skipped in favour of the next valid object.
    text = '{not valid} then {"a": 1}'
    assert llm.parse_json_response(text) == {"a": 1}


def test_parse_json_response_no_object_raises():
    with pytest.raises(llm.LLMUnavailable):
        llm.parse_json_response("prose with no object at all")


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


def test_resolve_model_degrades_down_the_ladder(monkeypatch):
    # 8b workspace with no 8b model deployed should prefer the next-best local
    # tier (4b) over the generic single-model default.
    monkeypatch.setenv(llm.ENV_MODEL, "default-model")
    monkeypatch.setenv(llm.ENV_MODEL_4B, "model-4b")
    monkeypatch.delenv(llm.ENV_MODEL_8B, raising=False)

    token = llm.set_workspace_ai_tier("local_8b")
    try:
        assert llm._resolve_model() == "model-4b"
    finally:
        llm.reset_workspace_ai_tier(token)

    # 8b with neither 8b nor 4b deployed falls through to the default model.
    monkeypatch.delenv(llm.ENV_MODEL_4B, raising=False)
    token = llm.set_workspace_ai_tier("local_8b")
    try:
        assert llm._resolve_model() == "default-model"
    finally:
        llm.reset_workspace_ai_tier(token)

    # 4b tier never reaches into an 8b model and degrades to default when unset.
    monkeypatch.setenv(llm.ENV_MODEL_8B, "model-8b")
    monkeypatch.delenv(llm.ENV_MODEL_4B, raising=False)
    token = llm.set_workspace_ai_tier("local_4b")
    try:
        assert llm._resolve_model() == "default-model"
    finally:
        llm.reset_workspace_ai_tier(token)


def test_resolve_model_defaults_to_ternary_bonsai(monkeypatch):
    # With no model env var configured, every tier resolves to the recommended
    # self-hosted default rather than a generic placeholder.
    for env_name in (llm.ENV_MODEL, llm.ENV_MODEL_4B, llm.ENV_MODEL_8B):
        monkeypatch.delenv(env_name, raising=False)
    assert llm.DEFAULT_LOCAL_MODEL == "Ternary-Bonsai-8B"
    for tier in ("", "local_4b", "local_8b"):
        token = llm.set_workspace_ai_tier(tier)
        try:
            assert llm._resolve_model() == "Ternary-Bonsai-8B"
        finally:
            llm.reset_workspace_ai_tier(token)


def test_is_compact_local_model():
    for name in ("Ternary-Bonsai-8B", "prism-ml/ternary-bonsai-4b", "BONSAI"):
        assert llm.is_compact_local_model(name)
    for name in ("gpt-4o-mini", "llama-3-70b", "", "default-model"):
        assert not llm.is_compact_local_model(name)


def test_adapt_system_prompt_compact_json_skill():
    # A JSON-expecting skill prompt gets a JSON-only directive for compact models.
    adapted = llm.adapt_system_prompt(
        "Return strict JSON. Be conservative.", "Ternary-Bonsai-8B"
    )
    assert adapted is not None
    assert "Return strict JSON" in adapted
    assert "ONLY a single JSON object" in adapted


def test_adapt_system_prompt_compact_prose_skill():
    # A prose skill prompt gets a brevity directive (not a JSON one).
    adapted = llm.adapt_system_prompt("Be concise and concrete.", "ternary-bonsai-8b")
    assert adapted is not None
    assert "three short sentences" in adapted
    assert "JSON" not in adapted


def test_adapt_system_prompt_noop_for_large_model():
    # Larger / hosted-class models keep the original prompt unchanged.
    assert llm.adapt_system_prompt("Return strict JSON.", "gpt-4o-mini") == (
        "Return strict JSON."
    )
    assert llm.adapt_system_prompt(None, "gpt-4o-mini") is None


def test_adapt_system_prompt_preserves_none_for_compact_model():
    # A caller that sends no system prompt must not have one synthesised, even
    # for compact models: the helper only tunes an existing prompt.
    assert llm.adapt_system_prompt(None, "Ternary-Bonsai-8B") is None
    assert llm.adapt_system_prompt(None, "ternary-bonsai-4b") is None


def test_call_llm_adapts_system_prompt_for_compact_model(monkeypatch):
    # The choke point applies model-aware prompt adaptation before dispatch.
    monkeypatch.delenv(llm.ENV_MODEL, raising=False)
    monkeypatch.delenv(llm.ENV_MODEL_4B, raising=False)
    monkeypatch.delenv(llm.ENV_MODEL_8B, raising=False)
    monkeypatch.setenv(llm.ENV_PROVIDER, "local")
    monkeypatch.setenv(llm.ENV_BASE_URL, "http://127.0.0.1:9")

    captured: dict[str, str | None] = {}

    def fake_chat(base_url, model, prompt, system, max_tokens):
        captured["model"] = model
        captured["system"] = system
        return "{}"

    monkeypatch.setattr(llm, "_chat_completion", fake_chat)
    llm.call_llm("hello", system="Return strict JSON.")
    assert captured["model"] == "Ternary-Bonsai-8B"
    assert captured["system"] is not None
    assert "ONLY a single JSON object" in captured["system"]
