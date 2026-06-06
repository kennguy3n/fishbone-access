"""Shared LLM client for the access-ai-agent skills.

Every skill has two code paths:

1. A deterministic, rule-based implementation that scores/decides purely from
   the request payload. This is the path exercised by the test suite and the
   path used whenever no LLM provider is configured.
2. An optional LLM-backed enrichment: when a *local* model provider is
   configured (``ACCESS_AI_LLM_PROVIDER=local-4b`` / ``local-8b`` / ``local``),
   the skill asks the model for a structured opinion and merges it with the
   deterministic result.

``call_llm`` is the single choke point for provider selection and the
fail-safe contract: when the provider is unset/``stub``/``deterministic``, when
the workspace tier pins ``deterministic``, or when the network call fails, it
raises :class:`LLMUnavailable`. Skills catch that and fall back to their
deterministic logic, so a momentarily-unreachable model never turns into a
hard failure of a privileged decision.

Zero-data-leakage guarantee: external SaaS providers (OpenAI, Anthropic, …) are
rejected at boot by :func:`assert_provider_allowed`. Access-control signals
never leave the operator's trust boundary; only locally-hosted, OpenAI-API-
compatible inference servers (vLLM, Ollama, TGI, …) are permitted.
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
from collections.abc import Callable
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Per-request workspace AI tier, read off the /a2a/invoke envelope by main.py
# and set before the skill runs. asyncio.to_thread copies the current context
# onto the worker thread (PEP 567), so call_llm reads it transparently.
#
# Recognised values:
#   * "deterministic" — short-circuit before any HTTP call (Base plan).
#   * "local_4b" — use ACCESS_AI_LLM_MODEL_4B (Pro plan).
#   * "local_8b" — use ACCESS_AI_LLM_MODEL_8B (Ultimate plan).
#   * "" / unrecognised — use ACCESS_AI_LLM_MODEL (single-model default).
_workspace_ai_tier: contextvars.ContextVar[str] = contextvars.ContextVar(
    "workspace_ai_tier", default=""
)

# Test seam: a callable (prompt, system) -> str installed by the test suite to
# simulate an LLM without a network. Deliberately a module global (NOT a
# contextvar) so it is visible from the worker thread that runs a skill even
# when the test installs it from a different thread (e.g. Starlette TestClient
# runs the app in a portal thread). Reset via reset_test_provider.
_test_provider: Callable[[str, str | None], str] | None = None

# Provider slugs that point at a locally-hosted, OpenAI-compatible server.
LOCAL_PROVIDERS: frozenset[str] = frozenset({"local", "local-4b", "local-8b"})

# Provider slugs that short-circuit to the deterministic path (no model call).
DETERMINISTIC_PROVIDERS: frozenset[str] = frozenset({"", "stub", "deterministic", "none"})

# External SaaS providers — forbidden in this deployment. Listing one in
# ACCESS_AI_LLM_PROVIDER is a boot-time fatal, not a silent downgrade.
EXTERNAL_LLM_PROVIDERS: frozenset[str] = frozenset(
    {"openai", "anthropic", "azure", "azure-openai", "bedrock", "vertex", "vertexai", "google", "cohere", "mistral", "groq"}
)

ENV_PROVIDER = "ACCESS_AI_LLM_PROVIDER"
ENV_BASE_URL = "ACCESS_AI_LLM_BASE_URL"
ENV_API_KEY = "ACCESS_AI_LLM_API_KEY"
ENV_MODEL = "ACCESS_AI_LLM_MODEL"
ENV_MODEL_4B = "ACCESS_AI_LLM_MODEL_4B"
ENV_MODEL_8B = "ACCESS_AI_LLM_MODEL_8B"

# Bound a single inference call so a slow model cannot stall the agent past the
# Go client's own 5s deadline.
_LLM_TIMEOUT_SECONDS = 4.0


class LLMUnavailable(RuntimeError):
    """Raised when no usable LLM is available (unconfigured, tier-pinned to
    deterministic, or the model call failed). Skills catch this and fall back
    to their deterministic implementation."""


class ExternalProviderError(ValueError):
    """Raised at boot when ACCESS_AI_LLM_PROVIDER names an external SaaS
    provider. The agent refuses to start rather than risk exfiltrating
    access-control signals to a third party."""


def set_workspace_ai_tier(tier: str) -> contextvars.Token[str]:
    """Set the per-request workspace AI tier; returns a token for reset."""
    return _workspace_ai_tier.set((tier or "").strip().lower())


def reset_workspace_ai_tier(token: contextvars.Token[str]) -> None:
    _workspace_ai_tier.reset(token)


def set_test_provider(
    fn: Callable[[str, str | None], str],
) -> Callable[[str, str | None], str] | None:
    """Install a fake LLM for tests. ``fn(prompt, system)`` returns the model's
    raw text. Returns the previous provider; pass it to
    :func:`reset_test_provider`."""
    global _test_provider
    prev = _test_provider
    _test_provider = fn
    return prev


def reset_test_provider(prev: Callable[[str, str | None], str] | None) -> None:
    global _test_provider
    _test_provider = prev


def configured_provider() -> str:
    return os.environ.get(ENV_PROVIDER, "").strip().lower()


def assert_provider_allowed() -> None:
    """Boot guard: reject external SaaS providers. Called once at startup."""
    provider = configured_provider()
    if provider in EXTERNAL_LLM_PROVIDERS:
        raise ExternalProviderError(
            f"{ENV_PROVIDER}={provider!r} is an external LLM provider, which is forbidden in "
            "access-ai-agent (zero-data-leakage). Use a locally-hosted, OpenAI-compatible "
            f"server via {ENV_PROVIDER}=local|local-4b|local-8b and {ENV_BASE_URL}."
        )


def _resolve_model() -> str:
    """Pick the model id for the current workspace tier, falling back to the
    single-model default."""
    tier = _workspace_ai_tier.get()
    if tier == "local_8b":
        model = os.environ.get(ENV_MODEL_8B, "").strip()
        if model:
            return model
    if tier == "local_4b":
        model = os.environ.get(ENV_MODEL_4B, "").strip()
        if model:
            return model
    return os.environ.get(ENV_MODEL, "").strip() or "local-default"


def call_llm(prompt: str, *, system: str | None = None, max_tokens: int = 512) -> str:
    """Run one completion against the configured local model and return its raw
    text. Raises :class:`LLMUnavailable` when no model should/can be called.

    Resolution order:
      1. The workspace tier: ``deterministic`` short-circuits (hard no-model).
      2. A test provider, if installed (test seam).
      3. ACCESS_AI_LLM_PROVIDER: deterministic slugs short-circuit; local slugs
         issue an OpenAI-compatible chat-completions request; external slugs
         raise (defence in depth — also guarded at boot).
    """
    # The deterministic tier is a hard "no model" contract and short-circuits
    # before any provider OR the test seam, so a workspace pinned to
    # deterministic always exercises the rule-based path.
    if _workspace_ai_tier.get() == "deterministic":
        raise LLMUnavailable("workspace tier pinned to deterministic")

    test_fn = _test_provider
    if test_fn is not None:
        return test_fn(prompt, system)

    provider = configured_provider()
    if provider in DETERMINISTIC_PROVIDERS:
        raise LLMUnavailable(f"no LLM provider configured (provider={provider!r})")
    if provider in EXTERNAL_LLM_PROVIDERS:
        raise ExternalProviderError(f"{ENV_PROVIDER}={provider!r} is an external provider; refusing to call it")
    if provider not in LOCAL_PROVIDERS:
        raise LLMUnavailable(f"unknown LLM provider {provider!r}")

    base_url = os.environ.get(ENV_BASE_URL, "").strip()
    if not base_url:
        raise LLMUnavailable(f"{ENV_BASE_URL} is required for provider={provider!r}")

    return _chat_completion(base_url, _resolve_model(), prompt, system, max_tokens)


def _chat_completion(base_url: str, model: str, prompt: str, system: str | None, max_tokens: int) -> str:
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    headers = {"Content-Type": "application/json"}
    api_key = os.environ.get(ENV_API_KEY, "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    url = base_url.rstrip("/") + "/v1/chat/completions"
    body = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": 0.0}
    try:
        resp = httpx.post(url, json=body, headers=headers, timeout=_LLM_TIMEOUT_SECONDS)
        resp.raise_for_status()
        data = resp.json()
        return str(data["choices"][0]["message"]["content"])
    except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
        raise LLMUnavailable(f"local LLM call failed: {exc}") from exc


def parse_json_response(text: str) -> dict[str, Any]:
    """Parse a model's text as a JSON object, tolerating a ```json fenced block.
    Raises :class:`LLMUnavailable` when the text is not a JSON object so the
    caller falls back to deterministic logic rather than trusting garbage."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        # Strip a leading ```json / ``` fence and the trailing fence.
        cleaned = cleaned.split("\n", 1)[-1] if "\n" in cleaned else ""
        if cleaned.endswith("```"):
            cleaned = cleaned[: -len("```")]
        cleaned = cleaned.strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise LLMUnavailable(f"LLM response was not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LLMUnavailable("LLM response JSON was not an object")
    return parsed
