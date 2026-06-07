"""connector_setup_assistant skill.

Guides an operator through wiring a new connector / IdP. It maps the requested
provider to the correct iam-core Connection strategy slug (per the shared
iam-core integration contract) and explains the required configuration.
Advisory only — the Go side treats the explanation as best-effort.
"""
from __future__ import annotations

import logging
from typing import Any

from .errors import SkillError
from .llm import LLMUnavailable, call_llm

logger = logging.getLogger(__name__)

# Connector / IdP type → iam-core Connection strategy slug (authoritative map
# from the shared iam-core contract). Okta/Ping/OneLogin/JumpCloud/Auth0 use the
# generic "oidc" strategy.
PROVIDER_STRATEGY = {
    "entra": "microsoft",
    "azure": "microsoft",
    "azuread": "microsoft",
    "azure_ad": "microsoft",
    "microsoft": "microsoft",
    "google": "google-oauth2",
    "google_workspace": "google-oauth2",
    "gsuite": "google-oauth2",
    "okta": "oidc",
    "ping": "oidc",
    "onelogin": "oidc",
    "jumpcloud": "oidc",
    "auth0": "oidc",
    "zoho": "zoho",
    "github": "github",
    "saml": "saml",
    "oidc": "oidc",
}


def _strategy_for(provider: str) -> str | None:
    return PROVIDER_STRATEGY.get(provider.strip().lower().replace("-", "_").replace(" ", "_"))


def _deterministic(payload: dict[str, Any]) -> str:
    provider = str(payload.get("provider", "") or "").strip()
    strategy = _strategy_for(provider)
    if strategy is None:
        return (
            f"Provider {provider!r} has no known iam-core strategy mapping. Supported providers: "
            f"{sorted(PROVIDER_STRATEGY)}. For a generic OIDC IdP use strategy 'oidc'."
        )
    return (
        f"Create an iam-core Connection for {provider!r} with strategy '{strategy}' via "
        "POST /api/v1/management/connections. Supply the IdP client_id/client_secret and the "
        "redirect URI, then call .../connections/{id}/test to verify connectivity before enabling "
        "with .../connections/{id}/toggle. Secrets are sealed at rest (AES-GCM)."
    )


def _llm_enrich(payload: dict[str, Any], strategy_hint: str) -> str | None:
    prompt = (
        "You help configure an SSO/identity connector against iam-core. Given the JSON, write 2-4 "
        f"sentences of setup guidance. The correct iam-core strategy slug is '{strategy_hint}'. "
        "Plain text, no JSON.\n"
        f"Request: {payload}"
    )
    try:
        text = call_llm(prompt, system="Be concise and concrete; reference the iam-core Connections API.")
    except LLMUnavailable:
        return None
    text = text.strip()
    return text or None


def run(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SkillError("payload must be an object")
    provider = payload.get("provider")
    if not provider or not isinstance(provider, str):
        raise SkillError("provider is required and must be a string")

    strategy = _strategy_for(provider)
    explanation = None
    if strategy is not None:
        explanation = _llm_enrich(payload, strategy)
    explanation = explanation or _deterministic(payload)
    return {"explanation": explanation, "reason": f"strategy={strategy or 'unknown'}"}
