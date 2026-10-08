from app.checks import spf
from app.checks.base import CheckContext, Status
from tests.fakes import FakeResolver


def run(records: dict[str, list[str]], domain="example.com"):
    r = FakeResolver()
    for name, txt in records.items():
        r.set(name, "TXT", txt)
    return spf.run(CheckContext(domain, r))


def test_missing():
    assert run({}).status is Status.FAIL


def test_multiple_records():
    f = run({"example.com": ["v=spf1 -all", "v=spf1 ~all"]})
    assert f.status is Status.FAIL and "More than one" in f.explanation


def test_ignores_non_spf_txt():
    f = run({"example.com": ["google-site-verification=abc", "v=spf1 include:_spf.google.com -all"],
             "_spf.google.com": ["v=spf1 ip4:1.2.3.4 -all"]})  # fmt: skip
    assert f.status is Status.PASS and f.evidence["dns_lookups"] == 1


def test_hard_fail_passes():
    assert run({"example.com": ["v=spf1 ip4:1.2.3.4 -all"]}).status is Status.PASS


def test_softfail_passes_with_note():
    f = run({"example.com": ["v=spf1 ip4:1.2.3.4 ~all"]})
    assert f.status is Status.PASS and "stricter" in f.explanation


def test_plus_all_and_question_all_fail():
    assert run({"example.com": ["v=spf1 +all"]}).status is Status.FAIL
    assert run({"example.com": ["v=spf1 all"]}).status is Status.FAIL
    assert run({"example.com": ["v=spf1 ?all"]}).status is Status.FAIL


def test_no_all_fails():
    assert run({"example.com": ["v=spf1 ip4:1.2.3.4"]}).status is Status.FAIL


def test_case_insensitive():
    assert run({"example.com": ["V=SPF1 IP4:1.2.3.4 -ALL"]}).status is Status.PASS


def test_counts_nested_lookups():
    f = run({
        "example.com": ["v=spf1 include:a.test include:b.test mx a -all"],
        "a.test": ["v=spf1 include:c.test -all"],
        "b.test": ["v=spf1 ip4:1.1.1.1 -all"],
        "c.test": ["v=spf1 a -all"],
    })  # fmt: skip
    assert f.evidence["dns_lookups"] == 6 and f.status is Status.PASS


def test_over_limit_fails():
    includes = " ".join(f"include:i{n}.test" for n in range(11))
    recs = {"example.com": [f"v=spf1 {includes} -all"]}
    recs.update({f"i{n}.test": ["v=spf1 ip4:1.1.1.1 -all"] for n in range(11)})
    f = run(recs)
    assert f.status is Status.FAIL and "limit is 10" in f.explanation


def test_exactly_ten_warns():
    includes = " ".join(f"include:i{n}.test" for n in range(10))
    recs = {"example.com": [f"v=spf1 {includes} -all"]}
    recs.update({f"i{n}.test": ["v=spf1 ip4:1.1.1.1 -all"] for n in range(10)})
    assert run(recs).status is Status.WARN


def test_broken_include_fails():
    f = run({"example.com": ["v=spf1 include:gone.test -all"]})
    assert f.status is Status.FAIL and "gone.test has no SPF record" in f.explanation


def test_include_loop_detected():
    f = run(
        {
            "example.com": ["v=spf1 include:a.test -all"],
            "a.test": ["v=spf1 include:example.com -all"],
        }
    )
    assert f.status is Status.FAIL and "loop" in f.explanation


def test_redirect_uses_target_all():
    f = run(
        {"example.com": ["v=spf1 redirect=_spf.test"], "_spf.test": ["v=spf1 ip4:1.1.1.1 -all"]}
    )
    assert f.status is Status.PASS and f.evidence["dns_lookups"] == 1


def test_ptr_warns():
    assert run({"example.com": ["v=spf1 ptr -all"]}).status is Status.WARN
