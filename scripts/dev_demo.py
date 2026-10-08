"""Local UI development server with canned scan results. Never use this in production.

Runs the real app on http://127.0.0.1:8000. Every scan returns the same example findings and no
network lookups are made, so the report pages can be developed offline.
"""

from __future__ import annotations

import os
import time

import uvicorn

from app.checks.base import Finding, Status
from app.config import Settings
from app.main import create_app

DEMO_FINDINGS = [
    Finding("spf", Status.PASS, "SPF (who may send email as your domain)",
            "An SPF record is published and valid. '~all' marks other mail as suspicious; "
            "'-all' is stricter.",
            {"record": "v=spf1 include:spf.protection.outlook.com ~all", "dns_lookups": 3}),
    Finding("dmarc", Status.WARN, "DMARC (what receivers do with forged mail)",
            "DMARC is in monitoring mode (p=none). It reports problems but does not stop forged "
            "mail. No reporting address (rua) is set, so you will not see who sends as your domain.",
            {"record": "v=DMARC1; p=none", "policy": "none", "reporting_address": None}),
    Finding("dkim", Status.NOT_DETECTED, "DKIM (signed email)",
            "No DKIM key was found under the common selector names we tried. This does not prove "
            "DKIM is off: your provider may use a different selector name.",
            {"selectors_checked": ["default", "google", "selector1", "selector2"]}),
    Finding("tls_cert", Status.PASS, "TLS certificate",
            "The certificate is valid and trusted (61 days left).",
            {"issuer": "Let's Encrypt", "valid_until": "2026-12-08", "days_left": 61}),
    Finding("tls_versions", Status.PASS, "TLS versions",
            "Only modern TLS versions are accepted (TLS 1.2, TLS 1.3).",
            {"supported": ["TLS 1.2", "TLS 1.3"]}),
    Finding("https", Status.WARN, "HTTPS redirect and HSTS",
            "No usable HSTS header, so browsers are not told to always use HTTPS.",
            {"http": {"status": 301, "location": "https://example.com/"}, "hsts": None}),
    Finding("headers", Status.FAIL, "Security headers",
            "Missing: Content-Security-Policy, Referrer-Policy, Permissions-Policy.",
            {"X-Content-Type-Options": {"verdict": "ok"}}),
    Finding("cookies", Status.PASS, "Cookie flags", "The home page does not set any cookies.", {}),
    Finding("caa", Status.WARN, "CAA (who may issue certificates)",
            "No CAA record was found. A CAA record is optional hardening.", {}),
]  # fmt: skip


class NoDns:
    def query(self, name: str, rtype: str) -> list[str]:
        return []


DELAY = float(os.environ.get("DEMO_DELAY", "0"))  # seconds; lets you see the "checking" state


def demo_runner(resolver, domain):  # noqa: ARG001
    time.sleep(DELAY)
    return DEMO_FINDINGS


def main() -> None:
    settings = Settings(secret_key="demo-only", secure_cookies=False, hsts=False, _env_file=None)
    app = create_app(settings, NoDns(), scan_runner=demo_runner, sync_jobs=DELAY == 0)
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")


if __name__ == "__main__":
    main()
