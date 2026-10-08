"""Check 5: which TLS versions the server accepts.

Each version is tested with a handshake that offers only that version. Certificates are not
verified here, because this check is only about protocol support. No application data is sent.
"""

from __future__ import annotations

import ssl

from app.checks.base import Check, CheckContext, Finding, Status
from app.fetcher import FetchError

VERSIONS = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
]


def run(ctx: CheckContext) -> Finding:
    cid, title = "tls_versions", "TLS versions"
    if ctx.fetcher is None:
        raise FetchError("No fetcher available.")
    # If the server cannot be reached at all this raises, and the engine records an error.
    ctx.fetcher.tls_probe(ctx.domain, verify=False)

    supported: list[str] = []
    refused: list[str] = []
    untested: list[str] = []
    for name, version in VERSIONS:
        try:
            r = ctx.fetcher.tls_probe(
                ctx.domain, verify=False, min_version=version, max_version=version
            )
        except FetchError:
            refused.append(name)  # reset or closed when offered only this version
            continue
        if r.untestable:
            untested.append(name)
        elif r.ok:
            supported.append(name)
        else:
            refused.append(name)
    evidence = {"supported": supported, "not_supported": refused, "could_not_test": untested}

    legacy = [v for v in supported if v in ("TLS 1.0", "TLS 1.1")]
    modern = [v for v in supported if v in ("TLS 1.2", "TLS 1.3")]
    if not modern:
        return Finding(
            cid, Status.FAIL, title,
            "The server does not accept TLS 1.2 or TLS 1.3, which all current browsers expect.",
            evidence,
        )  # fmt: skip
    note = ""
    if untested:
        note = " " + ", ".join(untested) + " could not be tested from this server."
    if legacy:
        return Finding(
            cid, Status.WARN, title,
            "The server still accepts outdated " + " and ".join(legacy)
            + ", which have been deprecated since 2021. Turn them off." + note,
            evidence,
        )  # fmt: skip
    extra = "" if "TLS 1.3" in supported else " TLS 1.3 is not enabled, which is optional."
    return Finding(
        cid, Status.PASS, title,
        "Only modern TLS versions are accepted (" + ", ".join(modern) + ")." + extra + note,
        evidence,
    )  # fmt: skip


CHECK = Check("tls_versions", "TLS versions", run)
