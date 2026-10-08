"""Domain normalisation and validation (FR-02, SR-12).

Only registrable domains are accepted (example.com.au, not www.example.com.au), because the
ownership proof and the email checks apply to the organisational domain. Names under public
suffixes, including private ones such as github.io, are rejected: users cannot publish TXT
records there.
"""

from __future__ import annotations

import ipaddress
import re

import idna
from publicsuffixlist import PublicSuffixList

_PSL_ALL = PublicSuffixList()
_PSL_ICANN = PublicSuffixList(only_icann=True)

MAX_INPUT_LENGTH = 300
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_INTERNAL_TLDS = {
    "local", "localhost", "internal", "intranet", "lan", "home", "corp", "private",
    "localdomain", "test", "invalid", "example", "onion", "arpa", "home.arpa",
}  # fmt: skip


class InvalidDomainError(ValueError):
    """The input is not an acceptable domain. The message is safe to show to the user."""


def normalise_domain(raw: str) -> str:
    """Return the lowercase ASCII (punycode) registrable domain or raise InvalidDomainError."""
    if not isinstance(raw, str):
        raise InvalidDomainError("Enter a domain name.")
    value = raw.strip().lower().rstrip(".")
    if not value:
        raise InvalidDomainError("Enter a domain name.")
    if len(value) > MAX_INPUT_LENGTH:
        raise InvalidDomainError("That is too long to be a domain name.")
    if any(c in value for c in "/\\:@?#[]% \t\r\n") or not value.isprintable():
        raise InvalidDomainError(
            "Enter just the domain, such as example.com (no http://, path or port)."
        )
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise InvalidDomainError("IP addresses are not allowed. Enter a domain name.")
    if re.fullmatch(r"[0-9.]+", value):
        raise InvalidDomainError("That does not look like a domain name.")

    try:
        ascii_name = idna.encode(value, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise InvalidDomainError("That is not a valid domain name.") from exc
    if len(ascii_name) > 253:
        raise InvalidDomainError("That is too long to be a domain name.")
    labels = ascii_name.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise InvalidDomainError("That is not a valid domain name.")
    if labels[-1] in _INTERNAL_TLDS or ".".join(labels[-2:]) in _INTERNAL_TLDS:
        raise InvalidDomainError("Internal and reserved names cannot be checked.")

    registrable_icann = _PSL_ICANN.privatesuffix(ascii_name)
    if registrable_icann is None:
        raise InvalidDomainError("That is a public suffix, not a domain you can own.")
    registrable_all = _PSL_ALL.privatesuffix(ascii_name)
    if registrable_all is None or registrable_all != registrable_icann:
        raise InvalidDomainError(
            "That is on a shared hosting suffix (such as github.io). "
            "You cannot publish DNS records there."
        )
    if registrable_icann != ascii_name:
        raise InvalidDomainError(f"Enter the main domain ({registrable_icann}), not a subdomain.")
    return ascii_name
