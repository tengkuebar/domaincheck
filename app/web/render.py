from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))  # autoescape on

# status -> (label, icon, css class). Always text + icon, never colour alone.
templates.env.globals["STATUS"] = {
    "pass": ("Good", "✓", "good"),
    "warn": ("Improve", "!", "warn"),
    "fail": ("Fix now", "✕", "bad"),
    "not_detected": ("Not detected", "?", "neutral"),
    "error": ("Could not check", "–", "neutral"),
}


def render(request: Request, name: str, status_code: int = 200, **context: Any) -> Any:
    context["csrf_token"] = request.state.session.csrf
    return templates.TemplateResponse(request, name, context, status_code=status_code)
