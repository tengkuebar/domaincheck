import pytest

from app.domains.validation import InvalidDomainError, normalise_domain


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("  Example.COM.  ", "example.com"),
        ("example.com.au", "example.com.au"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
    ],
)
def test_accepts_and_normalises(raw, expected):
    assert normalise_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "", "   ", "127.0.0.1", "10.0.0.1", "::1", "[::1]", "169.254.169.254", "1.2.3.4.5", "2130706433",
        "localhost", "example.local", "printer.lan", "host.internal", "foo.home.arpa", "x.test",
        "com", "com.au", "co.uk", "github.io", "foo.github.io", "herokuapp.com", "x.herokuapp.com",
        "www.example.com", "a.b.example.com.au",
        "http://example.com", "example.com/path", "example.com:8080", "user@example.com",
        "example.com?x=1", "exa mple.com", "example..com", "-bad.com", "bad-.com", "a_b.com",
        "a" * 64 + ".com", ("a" * 60 + ".") * 5 + "com", "x" * 400 + ".com",
        "exa\nmple.com", "exa\x00mple.com", "‮example.com",
    ],
)  # fmt: skip
def test_rejects(raw):
    with pytest.raises(InvalidDomainError):
        normalise_domain(raw)


def test_rejects_non_string():
    with pytest.raises(InvalidDomainError):
        normalise_domain(None)  # type: ignore[arg-type]
