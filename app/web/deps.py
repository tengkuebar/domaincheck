from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Form, HTTPException, Request

from app.dns import Resolver
from app.scanning.service import JobRunner
from app.scanning.store import ResultStore
from app.web.ratelimit import Limiters
from app.web.security import Session


def get_resolver(request: Request) -> Resolver:
    return request.app.state.resolver


def get_limiters(request: Request) -> Limiters:
    return request.app.state.limiters


def get_store(request: Request) -> ResultStore:
    return request.app.state.store


def get_jobs(request: Request) -> JobRunner:
    return request.app.state.jobs


def get_session(request: Request) -> Session:
    return request.state.session


def client_ip(request: Request) -> str:
    # X-Forwarded-For is client-controlled unless a trusted proxy sets it, so it is only read
    # when the deployment says there is exactly one trusted proxy in front.
    if request.app.state.settings.trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


Sess = Annotated[Session, Depends(get_session)]


def verify_csrf(sess: Sess, csrf_token: Annotated[str, Form()] = "") -> None:  # nosec B107
    if not sess.csrf_ok(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token.")


CsrfOk = Depends(verify_csrf)
