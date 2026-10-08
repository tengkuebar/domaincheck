from __future__ import annotations

import re

from fastapi.testclient import TestClient

from app.checks.base import Finding, Status
from app.config import Settings
from app.main import create_app
from tests.fakes import FakeResolver


def make_client(runner=None, **overrides) -> tuple[TestClient, FakeResolver]:
    resolver = FakeResolver()
    settings = Settings(secret_key="test-secret", secure_cookies=True, _env_file=None, **overrides)
    kwargs = {"scan_runner": runner} if runner else {}
    app = create_app(settings, resolver, sync_jobs=True, **kwargs)
    # https base URL so Secure cookies are sent back.
    return TestClient(app, base_url="https://testserver"), resolver


def csrf(client: TestClient, path: str = "/") -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).text)
    assert match
    return match.group(1)


def scan(client: TestClient, domain: str, token: str | None = None):
    return client.post(
        "/scan",
        data={"domain": domain, "csrf_token": token or csrf(client)},
        follow_redirects=False,
    )


def canned_runner(statuses: dict[str, Status] | None = None):
    """A scan runner returning fixed findings, so web tests need no DNS or network."""
    statuses = statuses or {"spf": Status.PASS, "dmarc": Status.WARN, "dkim": Status.NOT_DETECTED}

    def runner(resolver, domain):
        return [
            Finding(cid, st, cid.upper(), f"{cid} explanation for {domain}", {"k": "v"})
            for cid, st in statuses.items()
        ]

    return runner
