"""Unit tests for server-side mTLS helpers."""
from __future__ import annotations

import ssl

import pytest

from mtls import (
    ENV_CLIENT_CA_FILE,
    ENV_EXPECTED_CLIENT_IDENTITY,
    ENV_SERVER_CERT_FILE,
    ENV_SERVER_KEY_FILE,
    MTLSConfigError,
    ServerConfig,
    build_server_ssl_context,
    parse_expected_identities,
    peer_cert_matches_identity,
    peer_cert_uri_sans,
)


def test_parse_expected_identities():
    assert parse_expected_identities("") == ()
    assert parse_expected_identities("a") == ("a",)
    assert parse_expected_identities(" a , b ,, c ") == ("a", "b", "c")


def test_from_env_reads_all_fields(monkeypatch):
    monkeypatch.setenv(ENV_SERVER_CERT_FILE, "/s.crt")
    monkeypatch.setenv(ENV_SERVER_KEY_FILE, "/s.key")
    monkeypatch.setenv(ENV_CLIENT_CA_FILE, "/ca.crt")
    monkeypatch.setenv(ENV_EXPECTED_CLIENT_IDENTITY, "spiffe://a,spiffe://b")
    cfg = ServerConfig.from_env()
    assert cfg.is_enabled()
    assert cfg.expected_client_identities == ("spiffe://a", "spiffe://b")


def test_build_context_disabled_when_unset(monkeypatch):
    for var in (ENV_SERVER_CERT_FILE, ENV_SERVER_KEY_FILE, ENV_CLIENT_CA_FILE, ENV_EXPECTED_CLIENT_IDENTITY):
        monkeypatch.delenv(var, raising=False)
    cfg = ServerConfig.from_env()
    assert build_server_ssl_context(cfg) is None


def test_build_context_half_configured_raises():
    cfg = ServerConfig(server_cert_file="/s.crt", server_key_file="", client_ca_file="/ca.crt", expected_client_identities=())
    with pytest.raises(MTLSConfigError):
        build_server_ssl_context(cfg)


def test_build_context_identity_without_mtls_raises():
    # An identity pin set without any cert files would otherwise listen in
    # plaintext yet install a verifier that rejects every connection. Fail closed.
    cfg = ServerConfig(
        server_cert_file="",
        server_key_file="",
        client_ca_file="",
        expected_client_identities=("spiffe://caller",),
    )
    with pytest.raises(MTLSConfigError):
        build_server_ssl_context(cfg)


def test_build_context_no_identity_no_certs_is_plaintext():
    # No identity pin and no cert files: plain HTTP (dev / CI), not a fatal.
    cfg = ServerConfig(server_cert_file="", server_key_file="", client_ca_file="", expected_client_identities=())
    assert build_server_ssl_context(cfg) is None


def test_build_context_enabled(pki):
    cfg = ServerConfig(
        server_cert_file=pki.server_cert_file,
        server_key_file=pki.server_key_file,
        client_ca_file=pki.ca_file,
        expected_client_identities=(pki.client_spiffe_id,),
    )
    ctx = build_server_ssl_context(cfg)
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3


def test_peer_cert_uri_sans_extraction():
    peer = {"subjectAltName": (("URI", "spiffe://x"), ("DNS", "host"), ("URI", "spiffe://y"))}
    assert peer_cert_uri_sans(peer) == ("spiffe://x", "spiffe://y")
    assert peer_cert_uri_sans(None) == ()


def test_peer_cert_matches_identity():
    peer = {"subjectAltName": (("URI", "spiffe://allowed"),)}
    assert peer_cert_matches_identity(peer, ["spiffe://allowed"]) is True
    assert peer_cert_matches_identity(peer, ["spiffe://other"]) is False
    # Empty allowlist disables pinning (CA trust alone).
    assert peer_cert_matches_identity(peer, []) is True
    assert peer_cert_matches_identity(None, ["spiffe://allowed"]) is False
