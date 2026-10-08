from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from app.domains.validation import InvalidDomainError, normalise_domain
from app.web.dashboard import build_dashboard
from app.web.deps import CsrfOk, client_ip, get_jobs, get_limiters, get_store
from app.web.pdf import render_report_pdf
from app.web.render import render

router = APIRouter()


@router.get("/")
def home(request: Request):
    return render(request, "landing.html")


@router.get("/privacy")
def privacy(request: Request):
    return render(request, "privacy.html")


@router.post("/scan", dependencies=[CsrfOk])
def start_scan(request: Request, domain: Annotated[str, Form()] = ""):
    try:
        name = normalise_domain(domain)
    except InvalidDomainError as exc:
        return render(request, "landing.html", 400, error=str(exc), entered=domain[:100])

    limits = get_limiters(request)
    if not limits.scan_global.hit("all"):
        return render(request, "landing.html", 429, error="The service is busy. Try again later.")
    if not limits.scan_ip.hit(client_ip(request)):
        return render(
            request, "landing.html", 429, error="Too many scans from you. Try again later."
        )
    if not limits.scan_domain.hit(name):
        return render(
            request,
            "landing.html",
            429,
            error=f"{name} was scanned several times recently. Try again later.",
        )

    result = get_store(request).create(name)
    if not get_jobs(request).submit(result.id):
        return render(request, "landing.html", 503, error="Too many scans waiting. Try again soon.")
    return RedirectResponse(f"/r/{result.id}", status_code=303)


def _finished_report(request: Request, scan_id: str):
    result = get_store(request).get(scan_id)
    if result is None:
        raise HTTPException(
            status_code=404, detail="This report was not found. Reports are kept for one hour."
        )
    return result


@router.get("/r/{scan_id}")
def report(request: Request, scan_id: str):
    result = _finished_report(request, scan_id)
    context: dict[str, Any] = {}
    if result.status == "done":
        context = build_dashboard(result)
    return render(
        request,
        "report.html",
        scan=result,
        running=result.status in ("queued", "running"),
        **context,
    )


@router.get("/r/{scan_id}/report.pdf")
def report_pdf(request: Request, scan_id: str):
    result = _finished_report(request, scan_id)
    if result.status != "done":
        raise HTTPException(status_code=404, detail="This report is not ready yet.")
    pdf = render_report_pdf(result, build_dashboard(result))
    filename = "domaincheck-" + re.sub(r"[^a-z0-9.-]", "-", result.domain) + ".pdf"
    return Response(
        pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
