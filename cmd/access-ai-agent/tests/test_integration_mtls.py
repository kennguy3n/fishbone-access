"""End-to-end mTLS integration test for the access-ai-agent server.

Boots the real FastAPI app under uvicorn with an mTLS SSLContext (TLS 1.3,
CERT_REQUIRED against the in-test CA, plus the SPIFFE URI-SAN identity verifier
installed exactly as ``main.main()`` does), then drives it over real TLS:

  * a client presenting the CA-signed cert with the allowlisted URI-SAN succeeds;
  * a client presenting a cert signed by a *different* CA fails the handshake;
  * a client presenting no cert at all fails the handshake.

This is the Python half of the Go↔Python A2A contract; the Go half is covered by
internal/pkg/aiclient client tests plus the optional live cross-language test.
"""
from __future__ import annotations

import socket
import ssl
import threading
import time

import httpx
import pytest
import uvicorn

import main
from mtls import ServerConfig, build_server_ssl_context


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _ServerThread:
    def __init__(self, cfg: ServerConfig, port: int) -> None:
        ssl_ctx = build_server_ssl_context(cfg)
        config = uvicorn.Config(app=main.create_app(), host="127.0.0.1", port=port, log_level="warning")
        config.load()
        config.ssl = ssl_ctx
        main._install_identity_verifier(config, cfg.expected_client_identities)
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def __enter__(self) -> _ServerThread:
        self._thread.start()
        for _ in range(100):
            if self._server.started:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("uvicorn did not start in time")
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)


def _client_ctx(pki, cert_file: str, key_file: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=pki.ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    # The server leaf SANs cover 127.0.0.1; keep hostname checking on.
    return ctx


def test_mtls_authorized_client_succeeds(pki):
    port = _free_port()
    cfg = ServerConfig(
        server_cert_file=pki.server_cert_file,
        server_key_file=pki.server_key_file,
        client_ca_file=pki.ca_file,
        expected_client_identities=(pki.client_spiffe_id,),
    )
    with _ServerThread(cfg, port):
        ctx = _client_ctx(pki, pki.client_cert_file, pki.client_key_file)
        with httpx.Client(verify=ctx, base_url=f"https://127.0.0.1:{port}") as client:
            resp = client.post(
                "/a2a/invoke",
                json={
                    "skill_name": "access_risk_assessment",
                    "payload": {"role": "admin", "resource_external_id": "db-prod"},
                },
            )
            assert resp.status_code == 200
            assert resp.json()["risk_score"] == "high"


def test_mtls_rogue_ca_client_rejected(pki):
    port = _free_port()
    cfg = ServerConfig(
        server_cert_file=pki.server_cert_file,
        server_key_file=pki.server_key_file,
        client_ca_file=pki.ca_file,
        expected_client_identities=(pki.client_spiffe_id,),
    )
    with _ServerThread(cfg, port):
        ctx = _client_ctx(pki, pki.rogue_client_cert_file, pki.rogue_client_key_file)
        with httpx.Client(verify=ctx, base_url=f"https://127.0.0.1:{port}") as client:
            with pytest.raises((httpx.ConnectError, ssl.SSLError, httpx.RemoteProtocolError)):
                client.post("/a2a/invoke", json={"skill_name": "access_risk_assessment", "payload": {}})


def test_mtls_no_client_cert_rejected(pki):
    port = _free_port()
    cfg = ServerConfig(
        server_cert_file=pki.server_cert_file,
        server_key_file=pki.server_key_file,
        client_ca_file=pki.ca_file,
        expected_client_identities=(),
    )
    with _ServerThread(cfg, port):
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=pki.ca_file)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        with httpx.Client(verify=ctx, base_url=f"https://127.0.0.1:{port}") as client:
            with pytest.raises((httpx.ConnectError, ssl.SSLError, httpx.RemoteProtocolError)):
                client.post("/a2a/invoke", json={"skill_name": "access_risk_assessment", "payload": {}})


def test_mtls_identity_pin_rejects_unlisted_uri_san(pki):
    # CA trusts the client cert, but the allowlist names a DIFFERENT URI-SAN, so
    # the identity verifier in connection_made must drop the connection.
    port = _free_port()
    cfg = ServerConfig(
        server_cert_file=pki.server_cert_file,
        server_key_file=pki.server_key_file,
        client_ca_file=pki.ca_file,
        expected_client_identities=("spiffe://shieldnet/access/some-other-workload",),
    )
    with _ServerThread(cfg, port):
        ctx = _client_ctx(pki, pki.client_cert_file, pki.client_key_file)
        with httpx.Client(verify=ctx, base_url=f"https://127.0.0.1:{port}") as client:
            with pytest.raises((httpx.ConnectError, ssl.SSLError, httpx.RemoteProtocolError, httpx.ReadError)):
                client.post("/a2a/invoke", json={"skill_name": "access_risk_assessment", "payload": {}})
