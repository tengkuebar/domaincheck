"""List outbound-network code outside the allowed modules.

Usage: python find_outbound.py [root] [--allow DIR ...]
Exits 1 if anything is found, 0 if clean. Plain line-based matching: it is a tripwire for
"someone opened their own connection", not a full analyser, so read the diff as well.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_ALLOW = ("app/fetcher", "app/dns")

PATTERNS = [
    (
        re.compile(
            r"^\s*(?:import|from)\s+(httpx|requests|urllib3|aiohttp|http\.client|socket|smtplib|"
            r"ftplib|telnetlib|websockets|websocket|pycurl|dns\.resolver|dns\.query)\b"
        ),
        "network library import",
    ),
    (re.compile(r"^\s*(?:import|from)\s+urllib\.request\b"), "urllib.request import"),
    (re.compile(r"\burlopen\s*\("), "urlopen call"),
    (re.compile(r"\bsocket\.(?:create_connection|socket)\s*\("), "raw socket"),
    (
        re.compile(r"\.(?:wrap_socket|create_default_context)\s*\(|\bSSLContext\s*\("),
        "TLS context or wrap",
    ),
    (
        re.compile(r"subprocess\.\w+\([^)]*\b(?:curl|wget|nslookup|dig|ping)\b"),
        "shell network tool",
    ),
]


def scan(root: Path, allow: tuple[str, ...]) -> list[str]:
    hits: list[str] = []
    for path in sorted(root.rglob("*.py")):
        rel = path.as_posix()
        if any(part in rel for part in allow):
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for pattern, label in PATTERNS:
                if pattern.search(line):
                    hits.append(f"{rel}:{lineno}: {label}: {line.strip()}")
                    break
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default="app")
    parser.add_argument("--allow", nargs="*", default=list(DEFAULT_ALLOW))
    args = parser.parse_args()
    hits = scan(Path(args.root), tuple(args.allow))
    for hit in hits:
        print(hit)
    if hits:
        print(f"\n{len(hits)} outbound call(s) outside {', '.join(args.allow)}", file=sys.stderr)
        return 1
    print(f"clean: no outbound network code outside {', '.join(args.allow)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
