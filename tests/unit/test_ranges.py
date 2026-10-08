import pytest

from app.fetcher.ranges import is_blocked_ip


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1", "127.255.255.255", "0.0.0.0", "10.0.0.1", "172.16.0.1", "172.31.255.255",
        "192.168.1.1", "169.254.169.254", "169.254.0.1", "100.64.0.1", "224.0.0.1",
        "240.0.0.1", "255.255.255.255", "192.0.0.8", "198.18.0.1",
        "::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1",
        "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
        "64:ff9b::a00:1", "2002:7f00:1::", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "not-an-ip", "", "fe80::1%eth0",
    ],
)  # fmt: skip
def test_blocked(ip):
    assert is_blocked_ip(ip)


@pytest.mark.parametrize(
    "ip",
    ["8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"],
)
def test_allowed(ip):
    assert not is_blocked_ip(ip)
