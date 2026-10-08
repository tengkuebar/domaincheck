"""Check 3: DKIM under a short list of common selectors.

Selectors cannot be listed passively, so 'not detected' only means 'not found under these names'.
Key size policy: below 1024 bits fails, 1024 to 2047 warns, 2048 or more passes.
"""

from __future__ import annotations

import base64
import binascii

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from app.checks.base import Check, CheckContext, Finding, Status, worst
from app.checks.dmarc import parse_tags
from app.dns import DnsError

SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2",
    "mail", "dkim", "smtp", "mandrill", "mxvault", "everlytickey1", "zoho", "amazonses",
]  # fmt: skip
MIN_GOOD_BITS = 2048
MIN_ACCEPTABLE_BITS = 1024


def key_bits(tags: dict[str, str]) -> tuple[str, int | None]:
    """Return (key type, bits). Bits is None if the key cannot be parsed."""
    kind = tags.get("k", "rsa").lower()
    raw = "".join(tags.get("p", "").split())
    try:
        der = base64.b64decode(raw, validate=True)
        key = load_der_public_key(der)
    except (binascii.Error, ValueError, UnsupportedAlgorithm):
        return kind, None
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519", 256
    return kind, None


def _key_status(kind: str, bits: int | None) -> Status:
    if bits is None:
        return Status.FAIL
    if kind == "ed25519":
        return Status.PASS
    if bits >= MIN_GOOD_BITS:
        return Status.PASS
    if bits >= MIN_ACCEPTABLE_BITS:
        return Status.WARN
    return Status.FAIL


def run(ctx: CheckContext) -> Finding:
    cid, title = "dkim", "DKIM (signed email)"
    found: list[dict] = []
    errors = 0
    for selector in SELECTORS:
        try:
            values = ctx.resolver.query(f"{selector}._domainkey.{ctx.domain}", "TXT")
        except DnsError:
            errors += 1
            continue
        for value in values:
            tags = parse_tags(value)
            if "p" not in tags or tags.get("v", "DKIM1").upper() != "DKIM1":
                continue
            if not tags["p"].strip():
                found.append({"selector": selector, "revoked": True})
                continue
            kind, bits = key_bits(tags)
            found.append(
                {
                    "selector": selector,
                    "type": kind,
                    "bits": bits,
                    "status": _key_status(kind, bits),
                }
            )
    if errors == len(SELECTORS):
        raise DnsError("All DKIM selector lookups failed")

    active = [f for f in found if not f.get("revoked")]
    checked = {"selectors_checked": SELECTORS}
    if not active:
        return Finding(
            cid, Status.NOT_DETECTED, title,
            "No DKIM key was found under the common selector names we tried. This does not "
            "prove DKIM is off: your provider may use a different selector name.",
            checked | {"revoked": [f["selector"] for f in found]},
        )  # fmt: skip
    evidence = checked | {
        "keys": [{**f, "status": str(f["status"])} for f in active],
    }
    status = worst([f["status"] for f in active])
    if status is Status.PASS:
        text = "A DKIM key was found with a strong key size."
    elif status is Status.WARN:
        text = (
            "A DKIM key was found, but at least one key is 1024 bits. It still works, but "
            "2048 bits is recommended for new keys."
        )
    else:
        text = "A DKIM key was found, but at least one key is too weak or cannot be read."
    return Finding(cid, status, title, text, evidence)


CHECK = Check("dkim", "DKIM", run)
