import pytest

from app.checks import dmarc
from app.checks.base import CheckContext, Status
from tests.fakes import FakeResolver


def run(*txt: str):
    r = FakeResolver().set("_dmarc.example.com", "TXT", list(txt))
    return dmarc.run(CheckContext("example.com", r))


def test_missing():
    assert dmarc.run(CheckContext("example.com", FakeResolver())).status is Status.FAIL


def test_multiple():
    assert run("v=DMARC1; p=none", "v=DMARC1; p=reject").status is Status.FAIL


@pytest.mark.parametrize(
    "record", ["v=DMARC1; rua=mailto:a@x.test", "v=DMARC1; p=banana", "v=DMARC1;"]
)
def test_invalid_policy_fails(record):
    assert run(record).status is Status.FAIL


def test_none_warns():
    f = run("v=DMARC1; p=none; rua=mailto:a@example.com")
    assert f.status is Status.WARN and f.evidence["policy"] == "none"


@pytest.mark.parametrize("policy", ["quarantine", "reject"])
def test_enforcing_passes(policy):
    f = run(f"v=DMARC1; p={policy}; rua=mailto:a@example.com")
    assert f.status is Status.PASS and "reporting address" not in f.explanation


def test_missing_reporting_address_is_noted():
    f = run("v=DMARC1; p=reject")
    assert f.status is Status.PASS and "No reporting address" in f.explanation


def test_partial_pct_warns():
    assert run("v=DMARC1; p=reject; pct=50; rua=mailto:a@example.com").status is Status.WARN


def test_whitespace_and_case():
    assert run("v=DMARC1 ; P=Reject ; RUA=mailto:a@example.com").status is Status.PASS


def test_ignores_other_txt():
    assert run("something else", "v=DMARC1; p=reject").status is Status.PASS
