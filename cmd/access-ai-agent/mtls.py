"""access-ai-agent server-side mTLS helpers.

The Python agent is the server end of the A2A leg (ztna-api / workflow-engine →
access-ai-agent). This module builds the :class:`ssl.SSLContext` for TLS 1.3
mutual authentication and enforces an optional SPIFFE URI-SAN allowlist.

The env-var surface mirrors the Go client's ``A2A_MTLS_*`` contract field-for-
field so both halves of the platform read symmetric configuration:

  * ``A2A_MTLS_SERVER_CERT_FILE`` / ``A2A_MTLS_SERVER_KEY_FILE`` — the agent's
    leaf cert + private key (presented to clients).
  * ``A2A_MTLS_CLIENT_CA_FILE`` — the CA bundle the agent trusts to sign client
    certs (``ssl.CERT_REQUIRED``).
  * ``A2A_MTLS_EXPECTED_CLIENT_IDENTITY`` — optional comma-separated SPIFFE
    URI-SAN allowlist pinning which workloads may call the agent.

When none of the three cert files is set the agent falls back to plain HTTP
(dev / CI). A half-configured set (one or two of three) is a boot-time fatal,
never a silent downgrade to plaintext. Likewise, pinning
``A2A_MTLS_EXPECTED_CLIENT_IDENTITY`` without enabling mTLS is a boot-time fatal:
an identity allowlist is meaningless in plaintext and would reject all traffic.
"""
from __future__ import annotations

import logging
import os
import ssl
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

ENV_SERVER_CERT_FILE = "A2A_MTLS_SERVER_CERT_FILE"
ENV_SERVER_KEY_FILE = "A2A_MTLS_SERVER_KEY_FILE"
ENV_CLIENT_CA_FILE = "A2A_MTLS_CLIENT_CA_FILE"
ENV_EXPECTED_CLIENT_IDENTITY = "A2A_MTLS_EXPECTED_CLIENT_IDENTITY"


class MTLSConfigError(ValueError):
    """Raised when the mTLS env vars are half-configured (boot-time fatal)."""


@dataclass(frozen=True)
class ServerConfig:
    """The mTLS fields the agent reads from env vars, symmetric with the Go
    client's ``ClientTLSConfig``."""

    server_cert_file: str
    server_key_file: str
    client_ca_file: str
    expected_client_identities: tuple[str, ...]

    @classmethod
    def from_env(cls) -> ServerConfig:
        return cls(
            server_cert_file=os.environ.get(ENV_SERVER_CERT_FILE, "").strip(),
            server_key_file=os.environ.get(ENV_SERVER_KEY_FILE, "").strip(),
            client_ca_file=os.environ.get(ENV_CLIENT_CA_FILE, "").strip(),
            expected_client_identities=parse_expected_identities(
                os.environ.get(ENV_EXPECTED_CLIENT_IDENTITY, "")
            ),
        )

    def has_any_field(self) -> bool:
        return bool(self.server_cert_file or self.server_key_file or self.client_ca_file)

    def is_enabled(self) -> bool:
        return bool(self.server_cert_file and self.server_key_file and self.client_ca_file)


def parse_expected_identities(raw: str) -> tuple[str, ...]:
    """Split a comma-separated URI-SAN allowlist into a canonical tuple,
    dropping empty entries. Mirrors the Go side's parsing so the same env value
    is interpreted identically on both ends."""
    return tuple(s for s in (entry.strip() for entry in raw.split(",")) if s)


def build_server_ssl_context(cfg: ServerConfig) -> ssl.SSLContext | None:
    """Build a TLS 1.3 mutual-auth SSLContext, or ``None`` when mTLS is not
    configured. Raises :class:`MTLSConfigError` on a half-configured set."""
    if cfg.has_any_field() and not cfg.is_enabled():
        missing = [
            name
            for name, val in (
                (ENV_SERVER_CERT_FILE, cfg.server_cert_file),
                (ENV_SERVER_KEY_FILE, cfg.server_key_file),
                (ENV_CLIENT_CA_FILE, cfg.client_ca_file),
            )
            if not val
        ]
        raise MTLSConfigError(
            "access-ai-agent: mTLS is half-configured — set ALL of "
            f"{ENV_SERVER_CERT_FILE}, {ENV_SERVER_KEY_FILE}, {ENV_CLIENT_CA_FILE} together "
            f"(or none). Currently missing: {', '.join(missing)}"
        )
    # An identity allowlist only has meaning under mTLS: it pins WHICH client
    # certs may connect. Set without the cert files, the agent would listen in
    # plaintext yet still install the URI-SAN verifier, which sees no peer cert
    # and silently rejects *every* connection. Treat that as a boot-time fatal,
    # symmetric with the half-configured cert guard above, rather than a silent
    # black hole.
    if cfg.expected_client_identities and not cfg.is_enabled():
        raise MTLSConfigError(
            f"access-ai-agent: {ENV_EXPECTED_CLIENT_IDENTITY} pins a client-identity allowlist "
            f"but mTLS is not enabled — an identity allowlist requires mTLS. Set "
            f"{ENV_SERVER_CERT_FILE}, {ENV_SERVER_KEY_FILE}, {ENV_CLIENT_CA_FILE} together, or "
            f"unset {ENV_EXPECTED_CLIENT_IDENTITY}. Refusing to start in plaintext with an "
            "identity pin that would reject all traffic."
        )
    if not cfg.has_any_field():
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Server-side client-cert verification does not use hostname checking; the
    # URI-SAN allowlist is the identity-binding layer.
    ctx.check_hostname = False
    ctx.load_cert_chain(certfile=cfg.server_cert_file, keyfile=cfg.server_key_file)
    ctx.load_verify_locations(cafile=cfg.client_ca_file)
    return ctx


def peer_cert_uri_sans(peer_cert: dict[str, Any] | None) -> tuple[str, ...]:
    """Extract the URI-type subjectAltName entries from a getpeercert() dict."""
    if not peer_cert:
        return ()
    uris: list[str] = []
    for entry in peer_cert.get("subjectAltName", ()):
        if isinstance(entry, tuple) and len(entry) == 2 and entry[0] == "URI":
            uris.append(str(entry[1]))
    return tuple(uris)


def peer_cert_matches_identity(peer_cert: dict[str, Any] | None, expected: Iterable[str]) -> bool:
    """True iff the peer cert presents at least one expected URI-SAN. An empty
    allowlist disables pinning (CA trust alone) and returns True."""
    expected_set = {e for e in expected if e}
    if not expected_set:
        return True
    return bool(set(peer_cert_uri_sans(peer_cert)) & expected_set)


def log_boot_posture(cfg: ServerConfig, ctx: ssl.SSLContext | None) -> None:
    """Emit a single info/warn line describing the mTLS posture at boot."""
    if ctx is None:
        logger.info(
            "access-ai-agent: A2A mTLS DISABLED (no %s/%s/%s set; listening in plaintext)",
            ENV_SERVER_CERT_FILE, ENV_SERVER_KEY_FILE, ENV_CLIENT_CA_FILE,
        )
        return
    if not cfg.expected_client_identities:
        logger.warning(
            "access-ai-agent: A2A mTLS engaged but %s is unset — any client cert signed by the "
            "configured CA is accepted. Set %s to a SPIFFE URI allowlist to pin authorisation.",
            ENV_EXPECTED_CLIENT_IDENTITY, ENV_EXPECTED_CLIENT_IDENTITY,
        )
    else:
        logger.info(
            "access-ai-agent: A2A mTLS engaged (cert=%s, ca=%s, expected_identities=%s)",
            cfg.server_cert_file, cfg.client_ca_file, list(cfg.expected_client_identities),
        )
