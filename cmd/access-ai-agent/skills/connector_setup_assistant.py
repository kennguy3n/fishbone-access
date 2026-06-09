"""connector_setup_assistant skill.

Guides an operator through wiring a new connector / IdP. It maps the requested
provider to the correct iam-core Connection strategy slug (per the shared
iam-core integration contract), then returns a structured, step-by-step setup
plan (required scopes, field-mapping suggestions, common pitfalls) plus a short
prose explanation. Advisory only — the Go control plane treats the plan as
best-effort and is fail-OPEN: if this agent is unreachable the wizard still
works manually.

The plan is produced deterministically from the strategy family so it is stable
and auditable; the LLM, when reachable, only enriches the prose ``explanation``
(never the structured steps), mirroring the deterministic-core + optional-LLM
pattern used by the other skills.
"""
from __future__ import annotations

import copy
import logging
from typing import Any

from .errors import SkillError
from .llm import LLMUnavailable, call_llm

logger = logging.getLogger(__name__)

# Connector / IdP type → iam-core Connection strategy slug (authoritative map
# from the shared iam-core contract). Okta/Ping/OneLogin/JumpCloud/Auth0 use the
# generic "oidc" strategy.
#
# This map is deliberately NOT a mirror of the Go connector catalogue
# (internal/services/access/connector_catalog_data.go, ~160 providers). A
# "strategy" is an identity-federation pattern (Microsoft Graph, Google OAuth2,
# generic OIDC/SAML, GitHub, Zoho); only IdP/SSO-federation connectors map to
# one. The bulk of the catalogue is SaaS apps integrated via their own API
# tokens, which have no federation strategy and intentionally have no entry
# here. Hand-maintaining a 160-row parallel map would be the very drift source
# we want to avoid. A provider with no entry resolves to strategy None and the
# wizard fails OPEN: run() returns strategy="unknown", the explanation states no
# verified mapping exists (and lists the supported providers), and _plan_for
# emits a generic-OIDC best-effort plan whose pitfall tells the operator to
# confirm the provider speaks OIDC before proceeding. The Go caller treats the
# whole plan as advisory, so an unmapped provider degrades gracefully rather
# than blocking setup. Tests test_connector_unknown_provider_explains and
# test_connector_plan_for_unknown_provider_uses_generic_oidc pin this contract.
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

# Per-strategy setup profile: the admin console where the app/registration is
# created, the OAuth/API scopes the connector needs, the IdP-attribute →
# iam-core-field mapping suggestions, and the mistakes operators most often hit.
# These are concrete, provider-accurate defaults — not placeholders — so the
# plan is useful even when the LLM is unavailable.
STRATEGY_PROFILE: dict[str, dict[str, Any]] = {
    "microsoft": {
        "portal": "Microsoft Entra admin center → App registrations",
        "scopes": ["User.Read.All", "Group.Read.All", "Directory.Read.All", "AuditLog.Read.All"],
        "field_mappings": [
            {"source": "userPrincipalName", "target": "email"},
            {"source": "id", "target": "external_id"},
            {"source": "displayName", "target": "display_name"},
            {"source": "accountEnabled", "target": "active"},
        ],
        "pitfalls": [
            "Granting delegated instead of application permissions — the worker runs headless and needs application (app-only) consent.",
            "Forgetting to click 'Grant admin consent' after adding Graph permissions; tokens silently lack scope until you do.",
            "Using the client secret's *ID* instead of its *value* — the value is shown only once at creation.",
        ],
    },
    "google-oauth2": {
        "portal": "Google Cloud console → APIs & Services → Credentials (service account with domain-wide delegation)",
        "scopes": [
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.readonly",
        ],
        "field_mappings": [
            {"source": "primaryEmail", "target": "email"},
            {"source": "id", "target": "external_id"},
            {"source": "name.fullName", "target": "display_name"},
            # Directory API `suspended` has inverted polarity vs the platform's
            # `active` (suspended=true ⇒ active=false), so the mapping must be
            # flagged invert so the connector negates it instead of copying it
            # straight through.
            {"source": "suspended", "target": "active", "invert": True},
        ],
        "pitfalls": [
            "Skipping domain-wide delegation authorization in the Admin console — the service account can authenticate but reads zero users.",
            "Not impersonating a super-admin subject; Directory API calls 403 without an admin 'subject'.",
            "Enabling the Admin SDK API on the wrong GCP project.",
        ],
    },
    "oidc": {
        "portal": "the IdP's application catalogue (Okta/Ping/OneLogin/JumpCloud/Auth0 → create OIDC web app)",
        "scopes": ["openid", "profile", "email", "groups"],
        "field_mappings": [
            {"source": "sub", "target": "external_id"},
            {"source": "email", "target": "email"},
            {"source": "name", "target": "display_name"},
            {"source": "groups", "target": "groups"},
        ],
        "pitfalls": [
            "Redirect URI mismatch — it must match the platform callback exactly, including scheme and trailing slash.",
            "The 'groups' claim is not emitted by default on most IdPs; add a groups claim to the token or the SCIM/API token.",
            "Confusing the OIDC discovery issuer URL with the tenant admin URL.",
        ],
    },
    "saml": {
        "portal": "the IdP's SAML application catalogue (create a SAML 2.0 app)",
        "scopes": [],
        "field_mappings": [
            {"source": "NameID", "target": "external_id"},
            {"source": "email", "target": "email"},
            {"source": "displayName", "target": "display_name"},
            {"source": "memberOf", "target": "groups"},
        ],
        "pitfalls": [
            "Clock skew between IdP and SP invalidates assertions — keep both within ~3 minutes via NTP.",
            "Signing the response but not the assertion (or vice-versa) when the SP requires both.",
            "NameID format mismatch (emailAddress vs persistent) breaks account linking on re-login.",
        ],
    },
    "github": {
        "portal": "GitHub → Organization settings → GitHub Apps / OAuth Apps",
        "scopes": ["read:org", "read:user", "user:email"],
        "field_mappings": [
            {"source": "login", "target": "external_id"},
            {"source": "email", "target": "email"},
            {"source": "name", "target": "display_name"},
        ],
        "pitfalls": [
            "Org has not approved the OAuth app / GitHub App installation, so org membership reads come back empty.",
            "SSO-enforced orgs require an authorized PAT; an unauthorized token 200s but hides SSO-protected resources.",
        ],
    },
    "zoho": {
        "portal": "Zoho API console → Self Client / Server-based application",
        "scopes": ["AaaServer.profile.READ", "ZohoDirectory.users.READ", "ZohoDirectory.groups.READ"],
        "field_mappings": [
            {"source": "ZUID", "target": "external_id"},
            {"source": "Email", "target": "email"},
            {"source": "Display_Name", "target": "display_name"},
        ],
        "pitfalls": [
            "Using the wrong Zoho data-center domain (.com vs .eu vs .in) for the token and API base URL.",
            "Refresh tokens are bound to the data center and expire if unused for an extended period.",
        ],
    },
}

# Generic profile used when the provider maps to no known strategy: the operator
# is steered to the generic OIDC path, which is the safe default for an
# unrecognised IdP.
_GENERIC_PROFILE: dict[str, Any] = {
    "portal": "your IdP's application catalogue (use the generic OIDC integration)",
    "scopes": ["openid", "profile", "email"],
    "field_mappings": [
        {"source": "sub", "target": "external_id"},
        {"source": "email", "target": "email"},
    ],
    "pitfalls": [
        "No verified strategy mapping exists for this provider; confirm it speaks standard OIDC before proceeding.",
    ],
}


def _strategy_for(provider: str) -> str | None:
    return PROVIDER_STRATEGY.get(provider.strip().lower().replace("-", "_").replace(" ", "_"))


def _profile_for(strategy: str | None) -> dict[str, Any]:
    # Return a deep copy, never a reference into the module-level STRATEGY_PROFILE
    # / _GENERIC_PROFILE globals. The agent is a long-lived process serving
    # concurrent requests, and callers (e.g. _plan_for) reach into the profile's
    # nested field_mappings dicts; handing out the shared object would let any
    # future in-place edit corrupt the global state across every tenant's
    # subsequent requests. deepcopy makes each call's profile independent — the
    # profiles are tiny, so the cost is negligible.
    if strategy is None:
        return copy.deepcopy(_GENERIC_PROFILE)
    return copy.deepcopy(STRATEGY_PROFILE.get(strategy, _GENERIC_PROFILE))


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


def _plan_for(provider: str, strategy: str | None) -> list[dict[str, Any]]:
    """Build the ordered, structured setup steps for a provider.

    The steps are derived from the strategy profile so they carry concrete,
    provider-accurate scopes / field mappings / pitfalls. The shape matches the
    Go ConnectorSetupStep struct decoded by internal/pkg/aiclient.
    """
    profile = _profile_for(strategy)
    scopes = list(profile["scopes"])
    mappings = list(profile["field_mappings"])
    pitfalls = list(profile["pitfalls"])
    portal = profile["portal"]
    strategy_label = strategy or "oidc"

    steps: list[dict[str, Any]] = [
        {
            "step": 1,
            "title": f"Register the application in {portal}",
            "description": (
                f"In {portal}, create the application/registration that the {provider} connector "
                f"will authenticate as. Record the issuer/tenant identifier you will paste into the wizard."
            ),
            "required_scopes": [],
            "field_mappings": [],
            "common_pitfalls": [pitfalls[0]] if pitfalls else [],
            "estimated_minutes": 10,
        },
        {
            "step": 2,
            "title": "Grant the read scopes the connector needs",
            "description": (
                "Authorise the connector for the least-privilege scopes required to enumerate users"
                # Only claim "and groups" when a group-reading scope is actually
                # granted. The generic/unknown-provider profile asks for
                # openid/profile/email (no group scope), so the prose must match
                # required_scopes — exactly the path where accurate guidance
                # matters most, since the operator has no prior knowledge.
                + (" and groups" if any("group" in s.lower() for s in scopes) else "")
                + ". The connector never requests write scopes unless you enable provisioning."
            ),
            "required_scopes": scopes,
            "field_mappings": [],
            "common_pitfalls": pitfalls[1:2],
            "estimated_minutes": 5,
        },
        {
            "step": 3,
            "title": "Create credentials and copy the secret",
            "description": (
                "Generate the client secret / API key (or upload the service-account key) and copy it "
                "immediately — most IdPs reveal it only once. Paste it into the wizard's credential field; "
                "the platform seals it at rest with AES-GCM and never logs it."
            ),
            "required_scopes": [],
            "field_mappings": [],
            # Steps 1-2 take the first two pitfalls (registration, scopes); this
            # credential step takes the third AND absorbs any beyond it. The
            # open-ended slice (not [2:3]) guarantees a profile that later grows a
            # 4th pitfall surfaces it instead of silently dropping it. Behaviour
            # is unchanged for today's 2-3-pitfall profiles. A guard test
            # (test_connector_plan_surfaces_every_profile_pitfall) pins this.
            "common_pitfalls": pitfalls[2:],
            "estimated_minutes": 3,
        },
        {
            "step": 4,
            "title": "Map IdP attributes to platform identity fields",
            "description": (
                "Confirm the attribute mapping so synced identities resolve to the right platform fields. "
                "The defaults below match the provider's standard schema; override only if your directory is customised."
            ),
            "required_scopes": [],
            "field_mappings": mappings,
            "common_pitfalls": [],
            "estimated_minutes": 5,
        },
        {
            "step": 5,
            "title": "Test connectivity before enabling",
            "description": (
                f"Run the connector's Test action (strategy '{strategy_label}'), which calls VerifyPermissions "
                "against the provider using the sealed credentials. Resolve any scope/consent errors here — a "
                "green test is required before the connector can be enabled."
            ),
            "required_scopes": [],
            "field_mappings": [],
            "common_pitfalls": [],
            "estimated_minutes": 3,
        },
        {
            "step": 6,
            "title": "Enable the connector and run the first sync",
            "description": (
                "Create the connector instance and trigger the initial identity sync. The first run is a full "
                "enumeration; subsequent runs use the incremental delta cursor when the provider supports it."
            ),
            "required_scopes": [],
            "field_mappings": [],
            "common_pitfalls": [],
            "estimated_minutes": 5,
        },
    ]
    return steps


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
    model_used = False
    explanation = None
    if strategy is not None:
        explanation = _llm_enrich(payload, strategy)
        model_used = explanation is not None
    explanation = explanation or _deterministic(payload)
    return {
        "explanation": explanation,
        "reason": f"strategy={strategy or 'unknown'}",
        "strategy": strategy or "unknown",
        "steps": _plan_for(provider, strategy),
        "model_used": model_used,
    }
