"""Exercises the real handshake code against a local TLS server (loopback only, test-only)."""

import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.fetcher.tls import TlsConnectError, real_handshake


@pytest.fixture(scope="module")
def cert_files(tmp_path_factory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    d = tmp_path_factory.mktemp("tls")
    (d / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "k.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return d / "c.pem", d / "k.pem"


@pytest.fixture
def server(cert_files):
    started = []

    def start(max_version=None):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*map(str, cert_files))
        if max_version:
            ctx.maximum_version = max_version
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        sock.settimeout(0.2)
        stop = threading.Event()

        def loop():
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                except (TimeoutError, OSError):
                    continue
                try:
                    with ctx.wrap_socket(conn, server_side=True):
                        pass
                except (ssl.SSLError, OSError):
                    pass

        t = threading.Thread(target=loop, daemon=True)
        t.start()
        started.append((sock, stop, t))
        return sock.getsockname()[1]

    yield start
    for sock, stop, t in started:
        stop.set()
        t.join(timeout=2)
        sock.close()


def probe(port, **kw):
    return real_handshake("127.0.0.1", "localhost", port=port, timeout=3, **kw)


def test_unverified_handshake_returns_version_and_certificate(server):
    r = probe(server(), verify=False)
    assert r.ok and r.version == "TLSv1.3" and r.cipher
    assert r.cert.subject_cn == "localhost" and r.cert.sans == ["localhost"]
    assert 85 <= (r.cert.not_after - datetime.now(UTC)).days <= 90


def test_untrusted_certificate_is_a_verification_failure(server):
    r = probe(server(), verify=True)
    assert not r.ok and r.verify_failed and r.error


def test_server_limited_to_tls12_refuses_tls13_only_client(server):
    port = server(max_version=ssl.TLSVersion.TLSv1_2)
    only13 = probe(
        port, verify=False, min_version=ssl.TLSVersion.TLSv1_3, max_version=ssl.TLSVersion.TLSv1_3
    )
    only12 = probe(
        port, verify=False, min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2
    )
    assert not only13.ok and not only13.verify_failed
    assert only12.ok and only12.version == "TLSv1.2"


def test_refused_connection_raises():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(TlsConnectError):
        probe(port, verify=False)
