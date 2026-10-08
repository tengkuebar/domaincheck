import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.checks import dkim
from app.checks.base import CheckContext, Status
from app.dns import DnsError
from tests.fakes import FakeResolver


def _spki(public_key) -> str:
    der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


@pytest.fixture(scope="module")
def keys():
    gen = lambda bits: _spki(rsa.generate_private_key(65537, bits).public_key())  # noqa: E731
    return {
        # The library will not generate weak keys; a non-prime 512-bit modulus is enough to parse.
        512: _spki(rsa.RSAPublicNumbers(65537, (1 << 511) | 12345).public_key()),
        1024: gen(1024),
        2048: gen(2048),
        "ed": _spki(ed25519.Ed25519PrivateKey.generate().public_key()),
    }


def run(selector_records: dict[str, str], domain="example.com", resolver=None):
    r = resolver or FakeResolver()
    for sel, rec in selector_records.items():
        r.set(f"{sel}._domainkey.{domain}", "TXT", [rec])
    return dkim.run(CheckContext(domain, r))


def test_not_detected():
    f = run({})
    assert f.status is Status.NOT_DETECTED and "common selector" in f.explanation


def test_2048_passes(keys):
    f = run({"google": f"v=DKIM1; k=rsa; p={keys[2048]}"})
    assert f.status is Status.PASS and f.evidence["keys"][0]["bits"] == 2048


def test_1024_warns(keys):
    assert run({"default": f"v=DKIM1; p={keys[1024]}"}).status is Status.WARN


def test_512_fails(keys):
    assert run({"default": f"v=DKIM1; p={keys[512]}"}).status is Status.FAIL


def test_ed25519_passes(keys):
    assert run({"s1": f"v=DKIM1; k=ed25519; p={keys['ed']}"}).status is Status.PASS


def test_worst_key_wins(keys):
    f = run({"google": f"p={keys[2048]}", "default": f"p={keys[1024]}"})
    assert f.status is Status.WARN


def test_revoked_key_not_counted():
    f = run({"default": "v=DKIM1; p="})
    assert f.status is Status.NOT_DETECTED and f.evidence["revoked"] == ["default"]


def test_garbage_key_fails():
    assert run({"default": "v=DKIM1; p=!!notbase64!!"}).status is Status.FAIL
    assert run({"default": "v=DKIM1; p=QUJDRA=="}).status is Status.FAIL


def test_non_dkim_txt_ignored():
    assert run({"default": "hello world"}).status is Status.NOT_DETECTED


def test_partial_dns_errors_tolerated(keys):
    r = FakeResolver().set("default._domainkey.example.com", "TXT", DnsError("x"))
    f = run({"google": f"p={keys[2048]}"}, resolver=r)
    assert f.status is Status.PASS


def test_all_dns_errors_raise():
    r = FakeResolver()
    for sel in dkim.SELECTORS:
        r.set(f"{sel}._domainkey.example.com", "TXT", DnsError("x"))
    with pytest.raises(DnsError):
        dkim.run(CheckContext("example.com", r))
