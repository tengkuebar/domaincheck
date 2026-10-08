import pytest

from app.dns import DnsError, resolve_ips
from tests.fakes import FakeResolver


def test_combines_a_and_aaaa():
    r = FakeResolver().set("a.test", "A", ["1.2.3.4"]).set("a.test", "AAAA", ["2606::1"])
    assert resolve_ips(r, "a.test") == ["1.2.3.4", "2606::1"]


def test_one_family_failing_is_ok():
    r = FakeResolver().set("a.test", "A", ["1.2.3.4"]).set("a.test", "AAAA", DnsError("x"))
    assert resolve_ips(r, "a.test") == ["1.2.3.4"]


def test_all_failing_raises():
    r = FakeResolver().set("a.test", "A", DnsError("x")).set("a.test", "AAAA", DnsError("y"))
    with pytest.raises(DnsError):
        resolve_ips(r, "a.test")


def test_nxdomain_is_empty():
    assert resolve_ips(FakeResolver(), "none.test") == []
