"""The only module that makes DNS queries. Everything else takes a ``Resolver``."""

from __future__ import annotations

from typing import Protocol

import dns.exception
import dns.resolver

DNS_TIMEOUT = 2.0
DNS_LIFETIME = 5.0


class DnsError(Exception):
    """A lookup failed in a way that is not 'no such record' (timeout, SERVFAIL, ...)."""


class Resolver(Protocol):
    def query(self, name: str, rtype: str) -> list[str]:
        """Return record data as text. Empty list for NXDOMAIN or no records.

        TXT records come back as one string per record, with multi-chunk records joined.
        Raises DnsError for timeouts and server failures.
        """
        ...


class DnsResolver:
    def __init__(self, nameservers: list[str] | None = None) -> None:
        self._resolver = dns.resolver.Resolver(configure=nameservers is None)
        if nameservers is not None:
            self._resolver.nameservers = nameservers
        self._resolver.timeout = DNS_TIMEOUT
        self._resolver.lifetime = DNS_LIFETIME

    def query(self, name: str, rtype: str) -> list[str]:
        try:
            answer = self._resolver.resolve(name, rtype, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as exc:
            raise DnsError(f"{rtype} lookup for {name} failed: {type(exc).__name__}") from exc
        if answer.rrset is None:
            return []
        if rtype.upper() == "TXT":
            return [
                b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in answer.rrset
            ]
        return [rdata.to_text() for rdata in answer.rrset]


def resolve_ips(resolver: Resolver, host: str) -> list[str]:
    """A and AAAA addresses for ``host``. One family failing is fine if the other answers."""
    addresses: list[str] = []
    errors: list[DnsError] = []
    for rtype in ("A", "AAAA"):
        try:
            addresses.extend(resolver.query(host, rtype))
        except DnsError as exc:
            errors.append(exc)
    if not addresses and errors:
        raise errors[0]
    return addresses
