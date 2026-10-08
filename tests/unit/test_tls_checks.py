import ssl
from datetime import UTC, datetime, timedelta

import pytest

from app.checks import tls_cert, tls_versions
from app.checks.base import CheckContext, Status
from app.fetcher import CertInfo, FetchError, TlsResult
from tests.fakes import FakeResolver

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def cert(days_left: int) -> CertInfo:
    return CertInfo(
        subject_cn="example.com",
        issuer="Test CA",
        not_before=NOW - timedelta(days=60),
        not_after=NOW + timedelta(days=days_left, hours=1),
        sans=["example.com"],
    )


class StubFetcher:
    """Answers tls_probe from a function of (verify, min_version)."""

    def __init__(self, fn):
        self.fn = fn
        self.calls = []

    def tls_probe(self, host, *, verify=True, min_version=None, max_version=None):
        self.calls.append((host, verify, min_version, max_version))
        return self.fn(verify, min_version)


def ctx(fn) -> CheckContext:
    return CheckContext("example.com", FakeResolver(), StubFetcher(fn))


# ---- certificate -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("days", "status"),
    [
        (90, Status.PASS),
        (31, Status.PASS),
        (30, Status.WARN),
        (8, Status.WARN),
        (7, Status.FAIL),
        (0, Status.FAIL),
    ],
)
def test_cert_expiry_thresholds(days, status):
    c = ctx(lambda v, m: TlsResult(ok=True, version="TLSv1.3", cert=cert(days)))
    f = tls_cert.run(c, now=NOW)
    assert f.status is status and f.evidence["days_left"] == days


@pytest.mark.parametrize(
    ("error", "text"),
    [
        ("certificate has expired", "expired"),
        ("Hostname mismatch, certificate is not valid for 'example.com'.", "different domain"),
        ("self-signed certificate", "self-signed"),
        ("unable to get local issuer certificate", "chain is incomplete"),
        ("something odd", "did not validate"),
    ],
)
def test_cert_validation_failures(error, text):
    def fn(verify, m):
        if verify:
            return TlsResult(ok=False, verify_failed=True, error=error)
        return TlsResult(ok=True, cert=cert(-5))

    f = tls_cert.run(ctx(fn), now=NOW)
    assert f.status is Status.FAIL and text in f.explanation
    assert f.evidence["valid_until"]  # details come from the second, unverified handshake


def test_cert_handshake_failure_is_error_not_fail():
    with pytest.raises(FetchError):
        tls_cert.run(ctx(lambda v, m: TlsResult(ok=False, error="boom")), now=NOW)


# ---- versions --------------------------------------------------------------------------------

T = ssl.TLSVersion


def versions(accept: set, untestable: set = frozenset()):
    def fn(verify, minimum):
        assert verify is False
        if minimum is None:
            return TlsResult(ok=True)
        if minimum in untestable:
            return TlsResult(ok=False, untestable=True)
        return TlsResult(ok=minimum in accept)

    return fn


def test_modern_only_passes():
    f = tls_versions.run(ctx(versions({T.TLSv1_2, T.TLSv1_3})))
    assert f.status is Status.PASS and f.evidence["supported"] == ["TLS 1.2", "TLS 1.3"]


def test_tls12_only_passes_with_note():
    f = tls_versions.run(ctx(versions({T.TLSv1_2})))
    assert f.status is Status.PASS and "TLS 1.3 is not enabled" in f.explanation


def test_legacy_versions_warn():
    f = tls_versions.run(ctx(versions({T.TLSv1, T.TLSv1_1, T.TLSv1_2})))
    assert f.status is Status.WARN and "TLS 1.0 and TLS 1.1" in f.explanation


def test_no_modern_version_fails():
    assert tls_versions.run(ctx(versions({T.TLSv1_1}))).status is Status.FAIL
    assert tls_versions.run(ctx(versions(set()))).status is Status.FAIL


def test_untestable_versions_are_reported_not_assumed():
    f = tls_versions.run(ctx(versions({T.TLSv1_2, T.TLSv1_3}, untestable={T.TLSv1, T.TLSv1_1})))
    assert f.status is Status.PASS
    assert f.evidence["could_not_test"] == ["TLS 1.0", "TLS 1.1"]
    assert "could not be tested" in f.explanation


def test_connection_reset_for_a_version_counts_as_not_supported():
    def fn(verify, minimum):
        if minimum is T.TLSv1:
            raise FetchError("reset")
        return TlsResult(ok=minimum in (None, T.TLSv1_2, T.TLSv1_3))

    f = tls_versions.run(ctx(fn))
    assert f.status is Status.PASS and "TLS 1.0" in f.evidence["not_supported"]


def test_unreachable_server_raises():
    def fn(verify, minimum):
        raise FetchError("down")

    with pytest.raises(FetchError):
        tls_versions.run(ctx(fn))


def test_only_the_scanned_domain_is_probed():
    c = ctx(versions({T.TLSv1_2}))
    tls_versions.run(c)
    assert {call[0] for call in c.fetcher.calls} == {"example.com"}
