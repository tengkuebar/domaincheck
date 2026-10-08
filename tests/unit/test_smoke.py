from tests.web_helpers import make_client


def test_healthz():
    client, _ = make_client()
    assert client.get("/healthz").json() == {"status": "ok"}
