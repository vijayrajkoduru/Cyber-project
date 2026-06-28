"""Security hardening: headers, CORS lockdown, global exception handler."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    import main
    return TestClient(main.app)


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in r.headers
    assert r.headers.get("Referrer-Policy") == "no-referrer"


def test_cors_allows_configured_origin(client):
    r = client.get("/api/health", headers={"Origin": "http://localhost:3000"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_cors_rejects_unknown_origin(client):
    r = client.get("/api/health", headers={"Origin": "https://evil.example.com"})
    # Disallowed origin must NOT be echoed back as allowed.
    assert r.headers.get("access-control-allow-origin") != "https://evil.example.com"


def test_no_wildcard_cors(client):
    import main
    assert "*" not in main.CORS_ORIGINS


def test_global_exception_handler_registered(client):
    import main
    assert Exception in main.app.exception_handlers


def test_rate_limit_returns_429_when_exceeded(client, monkeypatch):
    import main
    monkeypatch.setattr(main, "_RATE_LIMIT_PER_MIN", 3)
    main._rate_hits.clear()
    # /api/health is exempt, so hit a non-exempt endpoint (401s still count).
    codes = [client.get("/api/auth/me").status_code for _ in range(5)]
    assert 429 in codes
    assert codes[:3] == [401, 401, 401]   # first 3 under the limit
    main._rate_hits.clear()
