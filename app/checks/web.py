"""Shared helpers for checks that look at the website."""

from __future__ import annotations

from app.checks.base import CheckContext
from app.fetcher import FetchError, FetchResult


def main_page(ctx: CheckContext) -> FetchResult:
    """The HTTPS home page (redirects followed), fetched once per scan and shared."""
    cached = ctx.cache.get("main_page")
    if isinstance(cached, FetchError):
        raise cached
    if cached is not None:
        return cached
    if ctx.fetcher is None:
        raise FetchError("No fetcher available.")
    try:
        result = ctx.fetcher.fetch(f"https://{ctx.domain}/")
    except FetchError as exc:
        ctx.cache["main_page"] = exc
        raise
    ctx.cache["main_page"] = result
    return result
