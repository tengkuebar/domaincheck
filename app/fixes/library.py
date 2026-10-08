"""Fix steps stored as data files (one JSON file per check, keyed by status)."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

PROVIDER_LABELS = {
    "microsoft365": "Microsoft 365",
    "google": "Google Workspace",
    "cpanel": "cPanel",
    "generic": "Steps",
}


@cache
def _load(check_id: str) -> dict[str, Any]:
    path = Path(__file__).parent / f"{check_id}.json"
    if not check_id.isidentifier() or not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def fix_steps(check_id: str, status: str) -> dict[str, Any] | None:
    """Fix guidance for a warn/fail/not_detected finding, or None.

    ``action`` is a short imperative label and ``effort`` a typical time estimate.
    """
    data = _load(check_id).get(status)
    if data is None:
        return None
    return {
        "summary": data["summary"],
        "action": data.get("action", data["summary"]),
        "effort": data.get("effort", ""),
        "providers": [
            {"name": PROVIDER_LABELS.get(key, key), "steps": steps}
            for key, steps in data["providers"].items()
        ],
    }
