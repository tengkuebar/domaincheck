"""Blocked address ranges for SSRF defence (SR-01)."""

from __future__ import annotations

import ipaddress

# Anything not globally routable is blocked via ``is_global``. These are extra ranges that
# Python treats as global or that deserve an explicit entry because they embed an IPv4 address
# or point at cloud metadata services.
_EXTRA_BLOCKED = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "100.64.0.0/10",  # carrier-grade NAT
        "169.254.0.0/16",  # link-local, includes cloud metadata 169.254.169.254
        "192.0.0.0/24",
        "198.18.0.0/15",
        "64:ff9b::/96",  # NAT64
        "64:ff9b:1::/48",
        "2001::/32",  # Teredo
        "2002::/16",  # 6to4
        "fd00:ec2::/32",  # AWS IPv6 metadata
        "fe80::/10",
    )
]


def is_blocked_ip(value: str) -> bool:
    """True if ``value`` must not be connected to. Unparseable input is blocked."""
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    return any(ip in net for net in _EXTRA_BLOCKED if net.version == ip.version)
