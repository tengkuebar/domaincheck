"""Only app/fetcher and app/dns may open connections (design rule: no check opens its own sockets)."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".claude" / "skills" / "ssrf-review" / "scripts" / "find_outbound.py"


def run(*args: str):
    return subprocess.run(  # noqa: S603  # nosec B603 - fixed local script, no user input
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, cwd=ROOT, check=False
    )


def test_app_has_no_outbound_code_outside_the_choke_point():
    result = run("app")
    assert result.returncode == 0, result.stdout


def test_script_catches_violations(tmp_path):
    bad = tmp_path / "app" / "checks"
    bad.mkdir(parents=True)
    (bad / "sneaky.py").write_text(
        "import httpx\nimport socket\ns = socket.create_connection(('x', 80))\n"
        "ctx = ssl.create_default_context()\n"
    )
    ok = tmp_path / "app" / "fetcher"
    ok.mkdir(parents=True)
    (ok / "allowed.py").write_text("import httpx\n")
    result = run(str(tmp_path / "app"))
    assert result.returncode == 1
    assert (
        "sneaky.py:1" in result.stdout
        and "sneaky.py:3" in result.stdout
        and "sneaky.py:4" in result.stdout
    )
    assert "allowed.py" not in result.stdout


def test_importing_ssl_for_constants_is_fine(tmp_path):
    (tmp_path / "x.py").write_text("import ssl\nV = ssl.TLSVersion.TLSv1_2\n")
    assert run(str(tmp_path)).returncode == 0
