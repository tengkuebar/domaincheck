from app.checks.base import Check, CheckContext, Finding, Status
from app.checks.engine import run_checks
from app.dns import DnsError
from app.fixes.library import fix_steps
from app.scoring import band, category_scores, gains, projected_score, score
from tests.fakes import FakeResolver


def f(cid, status):
    return Finding(cid, status, "t", "e")


def test_all_pass_is_100():
    assert score([f("spf", Status.PASS), f("dmarc", Status.PASS), f("dkim", Status.PASS)]) == 100


def test_all_fail_is_0():
    assert score([f("spf", Status.FAIL), f("dmarc", Status.FAIL)]) == 0


def test_weighted_mix():
    # spf 15 pass, dmarc 20 warn (10), dkim 10 not_detected (5) => 30/45
    got = score([f("spf", Status.PASS), f("dmarc", Status.WARN), f("dkim", Status.NOT_DETECTED)])
    assert got == round(100 * 30 / 45)


def test_gains_are_points_on_the_score_scale():
    findings = [f("spf", Status.PASS), f("dmarc", Status.WARN), f("dkim", Status.NOT_DETECTED)]
    g = gains(findings)
    assert g["spf"] == 0
    assert round(g["dmarc"], 1) == 22.2 and round(g["dkim"], 1) == 11.1
    # Fixing everything reaches 100.
    assert round(score(findings) + sum(g.values())) == 100


def test_projected_score_and_errors_ignored():
    findings = [f("dmarc", Status.FAIL), f("spf", Status.FAIL), f("dkim", Status.ERROR)]
    assert score(findings) == 0
    assert projected_score(findings, top_n=1) == round(100 * 20 / 35)  # dmarc is worth most
    assert projected_score(findings, top_n=3) == 100
    assert "dkim" not in gains(findings)
    assert projected_score([f("spf", Status.ERROR)]) is None


def test_category_scores_and_bands():
    cats = category_scores([f("spf", Status.PASS), f("dmarc", Status.FAIL), f("caa", Status.WARN)])
    by_key = {c["key"]: c for c in cats}
    assert by_key["email"]["pct"] == round(100 * 15 / 35)
    assert by_key["hardening"]["pct"] == 50 and "encryption" not in by_key
    assert category_scores([f("spf", Status.ERROR)])[0]["pct"] is None
    assert band(90) == ("good", "Strong") and band(60) == ("warn", "Fair")
    assert band(59) == ("bad", "Needs work") and band(None) is None


def test_every_check_has_a_category_and_a_weight():
    from app.checks.engine import ALL_CHECKS, OPTIONAL_CHECKS
    from app.scoring import CATEGORIES, WEIGHTS

    in_categories = {cid for c in CATEGORIES for cid in c.check_ids}
    for check in ALL_CHECKS + OPTIONAL_CHECKS:
        assert check.id in in_categories and check.id in WEIGHTS


def test_fix_entries_have_action_and_effort():
    for check_id, statuses in [
        ("spf", ["fail", "warn"]),
        ("dmarc", ["fail", "warn"]),
        ("dkim", ["not_detected", "warn", "fail"]),
        ("tls_cert", ["fail", "warn"]),
        ("tls_versions", ["warn", "fail"]),
        ("https", ["fail", "warn"]),
        ("headers", ["warn", "fail"]),
        ("cookies", ["fail", "warn"]),
        ("caa", ["warn"]),
        ("paths", ["fail"]),
    ]:
        for status in statuses:
            fix = fix_steps(check_id, status)
            assert fix["action"] and fix["effort"].endswith("min") and fix["providers"], (
                check_id,
                status,
            )


def test_errors_excluded_and_empty_is_none():
    assert score([f("spf", Status.PASS), f("dmarc", Status.ERROR)]) == 100
    assert score([f("spf", Status.ERROR)]) is None
    assert score([]) is None


def test_fix_steps_cover_main_providers():
    spf_fix = fix_steps("spf", "fail")
    names = [p["name"] for p in spf_fix["providers"]]
    assert names == ["Microsoft 365", "Google Workspace", "cPanel"]
    assert fix_steps("dkim", "not_detected") and fix_steps("dmarc", "warn")


def test_no_fix_for_pass_or_unknown():
    assert fix_steps("spf", "pass") is None
    assert fix_steps("nope", "fail") is None
    assert fix_steps("../spf", "fail") is None


def test_engine_turns_failures_into_error_findings():
    def dns_fail(ctx):
        raise DnsError("x")

    def crash(ctx):
        raise RuntimeError("secret internal detail")

    ctx = CheckContext("example.com", FakeResolver())
    out = run_checks(ctx, [Check("a", "A", dns_fail), Check("b", "B", crash)])
    assert [x.status for x in out] == [Status.ERROR, Status.ERROR]
    assert "secret" not in out[1].explanation


def test_engine_budget_exhausted():
    ctx = CheckContext("example.com", FakeResolver())
    out = run_checks(ctx, [Check("a", "A", lambda c: f("a", Status.PASS))], budget=-1)
    assert out[0].status is Status.ERROR and "ran out of time" in out[0].explanation
