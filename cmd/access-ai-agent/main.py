"""access-ai-agent: A2A skill server (FastAPI + mTLS).

The agent exposes a single skill-dispatch endpoint, ``POST /a2a/invoke``, that
the Go control plane (ztna-api / access-workflow-engine via internal/pkg/
aiclient) calls over mutual TLS. The request envelope is::

    {"skill_name": "<name>", "payload": {...}, "workspace_ai_tier": "..."}

and the response is a unified JSON object whose populated fields depend on the
skill (risk_score / risk_factors / decision / reason / explanation / anomalies /
recommendation). Routing is by ``skill_name`` only, so the client is
skill-name-agnostic.

Security posture (defence in depth):
  * mTLS (mtls.py): TLS 1.3, ``CERT_REQUIRED`` against the configured client CA,
    plus an optional SPIFFE URI-SAN allowlist enforced in the uvicorn protocol's
    ``connection_made`` — before any HTTP byte is read.
  * Bearer token: an optional ``X-API-Key`` (``ACCESS_AI_AGENT_API_KEY``) checked
    on /a2a/invoke. A leaked key alone fails at the TLS handshake; a leaked
    private key alone fails at the bearer check.

LLM posture: skills compute a deterministic result and optionally enrich it via a
locally-hosted, OpenAI-compatible model (skills/llm.py). External SaaS providers
are rejected at boot (zero-data-leakage).
"""
from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from mtls import ServerConfig, build_server_ssl_context, log_boot_posture
from skills import (
    access_anomaly_detection,
    access_review_automation,
    access_risk_assessment,
    connector_setup_assistant,
    pam_behavioural_analytics,
    pam_session_risk_assessment,
    policy_recommendation,
)
from skills.errors import SkillError
from skills.llm import assert_provider_allowed, reset_workspace_ai_tier, set_workspace_ai_tier

logger = logging.getLogger(__name__)

ENV_API_KEY = "ACCESS_AI_AGENT_API_KEY"
ENV_LISTEN_HOST = "ACCESS_AI_AGENT_HOST"
ENV_LISTEN_PORT = "ACCESS_AI_AGENT_PORT"

# skill_name → callable(payload) -> dict. The single source of truth for which
# skills the agent serves; the Go side's aiclient skill constants must match
# these keys.
SkillFn = Callable[[dict[str, Any]], dict[str, Any]]
SKILLS: dict[str, SkillFn] = {
    "access_risk_assessment": access_risk_assessment.run,
    "access_review_automation": access_review_automation.run,
    "access_anomaly_detection": access_anomaly_detection.run,
    "pam_session_risk_assessment": pam_session_risk_assessment.run,
    "pam_behavioural_analytics": pam_behavioural_analytics.run,
    "policy_recommendation": policy_recommendation.run,
    "connector_setup_assistant": connector_setup_assistant.run,
}


class InvokeRequest(BaseModel):
    """The /a2a/invoke envelope, byte-compatible with the Go aiclient."""

    skill_name: str = Field(..., min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    workspace_ai_tier: str = ""


def create_app() -> FastAPI:
    app = FastAPI(title="access-ai-agent", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, Any]:
        # Readiness includes the boot guard: a misconfigured (external) provider
        # makes the agent NOT ready rather than silently degrading.
        try:
            assert_provider_allowed()
        except ValueError as exc:
            return JSONResponse(status_code=503, content={"status": "unready", "error": str(exc)})  # type: ignore[return-value]
        return {"status": "ok", "skills": sorted(SKILLS)}

    @app.post("/a2a/invoke")
    async def invoke(
        req: InvokeRequest,
        x_api_key: str | None = Header(default=None),
    ) -> JSONResponse:
        if not _api_key_ok(x_api_key):
            return JSONResponse(status_code=401, content={"error": "invalid or missing X-API-Key"})

        skill = SKILLS.get(req.skill_name)
        if skill is None:
            return JSONResponse(status_code=404, content={"error": f"unknown skill {req.skill_name!r}"})

        token = set_workspace_ai_tier(req.workspace_ai_tier)
        try:
            # Skills are synchronous + may issue a (bounded) blocking LLM call;
            # run off the event loop. to_thread copies the contextvar (tier).
            result = await asyncio.to_thread(skill, req.payload)
        except SkillError as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})
        except Exception:  # noqa: BLE001 - surface as 500 with a log, never leak internals
            logger.exception("access-ai-agent: skill %r raised", req.skill_name)
            return JSONResponse(status_code=500, content={"error": "internal skill error"})
        finally:
            reset_workspace_ai_tier(token)

        return JSONResponse(status_code=200, content=result)

    return app


def _api_key_ok(provided: str | None) -> bool:
    """True when the configured API key is empty (auth disabled) or matches the
    provided header. Uses a constant-time compare to avoid timing leaks."""
    expected = os.environ.get(ENV_API_KEY, "").strip()
    if not expected:
        return True
    if not provided:
        return False
    import hmac

    return hmac.compare_digest(expected, provided.strip())


app = create_app()


def _install_identity_verifier(config: Any, expected: tuple[str, ...]) -> None:
    """Subclass uvicorn's HTTP protocol to enforce the SPIFFE URI-SAN allowlist
    in ``connection_made`` — before any HTTP byte is processed. uvicorn reads
    ``config.http_protocol_class`` per connection, so reassigning it here is
    sufficient. A no-op when the allowlist is empty (CA trust alone)."""
    if not expected:
        return
    original_proto = config.http_protocol_class

    from mtls import peer_cert_matches_identity, peer_cert_uri_sans

    class _IdentityVerifyingProtocol(original_proto):  # type: ignore[misc, valid-type]
        def connection_made(self, transport: Any) -> None:
            peer_cert = transport.get_extra_info("peercert")
            if not peer_cert_matches_identity(peer_cert, expected):
                logger.warning(
                    "access-ai-agent: rejecting connection; peer URI-SANs %s not in allowlist %s",
                    list(peer_cert_uri_sans(peer_cert)), list(expected),
                )
                transport.close()
                return
            super().connection_made(transport)

    config.http_protocol_class = _IdentityVerifyingProtocol


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # Fail the boot if an external LLM provider is configured.
    assert_provider_allowed()

    import uvicorn

    cfg = ServerConfig.from_env()
    ssl_ctx = build_server_ssl_context(cfg)
    log_boot_posture(cfg, ssl_ctx)

    host = os.environ.get(ENV_LISTEN_HOST, "0.0.0.0").strip() or "0.0.0.0"  # noqa: S104 - bind-all is intended in-cluster
    port = int(os.environ.get(ENV_LISTEN_PORT, "8443").strip() or "8443")

    config = uvicorn.Config(app=app, host=host, port=port, log_level="info")
    # uvicorn builds its SSLContext from ssl_certfile/keyfile during load(); we
    # instead inject the context built by mtls.build_server_ssl_context (TLS 1.3
    # floor + CERT_REQUIRED). Load first (sets config.loaded=True so _serve does
    # not rebuild and clobber config.ssl), then assign our context.
    config.load()
    config.ssl = ssl_ctx
    _install_identity_verifier(config, cfg.expected_client_identities)
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
