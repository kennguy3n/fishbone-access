"""Shared pytest fixtures: an in-test PKI for mTLS tests.

Generates a throwaway CA plus server and client leaf certificates (the client
carrying a SPIFFE URI-SAN) so the mTLS handshake can be exercised end-to-end
without any on-disk fixtures or external services.
"""
from __future__ import annotations

import datetime
import ipaddress
import os
import sys
from dataclasses import dataclass

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Make the agent package importable as top-level modules (main, mtls, skills).
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

CLIENT_SPIFFE_ID = "spiffe://shieldnet/access/workflow-engine"
SERVER_DNS_NAME = "access-ai-agent.local"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)


@dataclass(frozen=True)
class PKI:
    ca_cert_pem: bytes
    server_cert_file: str
    server_key_file: str
    client_cert_file: str
    client_key_file: str
    ca_file: str
    # A client cert signed by a *different* CA (should be rejected).
    rogue_client_cert_file: str
    rogue_client_key_file: str
    client_spiffe_id: str


def _self_signed_ca(name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    common_name: str,
    san: x509.SubjectAlternativeName,
    server_auth: bool,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _key()
    now = datetime.datetime.now(datetime.UTC)
    eku = x509.ExtendedKeyUsage(
        [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]
        if server_auth
        else [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(san, critical=False)
        .add_extension(eku, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture
def pki(tmp_path) -> PKI:  # type: ignore[no-untyped-def]
    ca_key, ca_cert = _self_signed_ca("shieldnet-test-ca")

    server_key, server_cert = _leaf(
        ca_key,
        ca_cert,
        SERVER_DNS_NAME,
        x509.SubjectAlternativeName(
            [x509.DNSName(SERVER_DNS_NAME), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        ),
        server_auth=True,
    )
    client_key, client_cert = _leaf(
        ca_key,
        ca_cert,
        "workflow-engine",
        x509.SubjectAlternativeName([x509.UniformResourceIdentifier(CLIENT_SPIFFE_ID)]),
        server_auth=False,
    )

    rogue_ca_key, rogue_ca_cert = _self_signed_ca("rogue-ca")
    rogue_key, rogue_cert = _leaf(
        rogue_ca_key,
        rogue_ca_cert,
        "rogue-client",
        x509.SubjectAlternativeName([x509.UniformResourceIdentifier("spiffe://rogue/client")]),
        server_auth=False,
    )

    d = str(tmp_path)
    paths = {
        "server_cert": os.path.join(d, "server.crt"),
        "server_key": os.path.join(d, "server.key"),
        "client_cert": os.path.join(d, "client.crt"),
        "client_key": os.path.join(d, "client.key"),
        "ca": os.path.join(d, "ca.crt"),
        "rogue_cert": os.path.join(d, "rogue.crt"),
        "rogue_key": os.path.join(d, "rogue.key"),
    }
    _write(paths["server_cert"], _pem_cert(server_cert))
    _write(paths["server_key"], _pem_key(server_key))
    _write(paths["client_cert"], _pem_cert(client_cert))
    _write(paths["client_key"], _pem_key(client_key))
    _write(paths["ca"], _pem_cert(ca_cert))
    _write(paths["rogue_cert"], _pem_cert(rogue_cert))
    _write(paths["rogue_key"], _pem_key(rogue_key))

    return PKI(
        ca_cert_pem=_pem_cert(ca_cert),
        server_cert_file=paths["server_cert"],
        server_key_file=paths["server_key"],
        client_cert_file=paths["client_cert"],
        client_key_file=paths["client_key"],
        ca_file=paths["ca"],
        rogue_client_cert_file=paths["rogue_cert"],
        rogue_client_key_file=paths["rogue_key"],
        client_spiffe_id=CLIENT_SPIFFE_ID,
    )
