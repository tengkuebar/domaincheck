"""Check 4: certificate validity, expiry date and chain."""

from __future__ import annotations

from datetime import UTC, datetime

from app.checks.base import Check, CheckContext, Finding, Status
from app.fetcher import FetchError

FAIL_DAYS = 7
WARN_DAYS = 30

_REASONS = {
    "certificate has expired": "The certificate has expired.",
    "Hostname mismatch": "The certificate is for a different domain name.",
    "self-signed": "The certificate is self-signed, so browsers will not trust it.",
    "unable to get local issuer certificate": (
        "The certificate chain is incomplete or the issuer is not trusted. Often the server "
        "is missing an intermediate certificate."
    ),
}


def _reason(message: str | None) -> str:
    for needle, text in _REASONS.items():
        if message and needle.lower() in message.lower():
            return text
    return f"The certificate did not validate ({message or 'unknown reason'})."


def run(ctx: CheckContext, now: datetime | None = None) -> Finding:
    cid, title = "tls_cert", "TLS certificate"
    if ctx.fetcher is None:
        raise FetchError("No fetcher available.")
    now = now or datetime.now(UTC)
    result = ctx.fetcher.tls_probe(ctx.domain, verify=True)
    if not result.ok and result.verify_failed:
        details = ctx.fetcher.tls_probe(ctx.domain, verify=False)
        evidence = {"error": result.error}
        if details.cert:
            evidence |= _cert_evidence(details.cert, now)
        return Finding(cid, Status.FAIL, title, _reason(result.error), evidence)
    if not result.ok or result.cert is None:
        raise FetchError("TLS handshake failed")

    evidence = _cert_evidence(result.cert, now)
    days = evidence["days_left"]
    if days <= FAIL_DAYS:
        status, text = Status.FAIL, f"The certificate expires in {days} days."
    elif days <= WARN_DAYS:
        status, text = Status.WARN, f"The certificate expires in {days} days. Renew it soon."
    else:
        status, text = Status.PASS, f"The certificate is valid and trusted ({days} days left)."
    return Finding(cid, status, title, text, evidence)


def _cert_evidence(cert, now: datetime) -> dict:
    return {
        "subject": cert.subject_cn,
        "issuer": cert.issuer,
        "valid_from": cert.not_before.date().isoformat(),
        "valid_until": cert.not_after.date().isoformat(),
        "days_left": (cert.not_after - now).days,
        "names": cert.sans,
    }


CHECK = Check("tls_cert", "TLS certificate", run)
