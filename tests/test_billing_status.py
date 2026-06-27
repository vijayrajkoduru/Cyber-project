"""Trial/billing status endpoints exist and reflect quota state (audit #27/46)."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    import main
    return TestClient(main.app)


@pytest.fixture()
def auth(client):
    r = client.post("/api/auth/register", json={
        "username": "billinguser", "email": "b@example.com", "password": "password123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_trial_status_returns_quota(client, auth):
    r = client.get("/api/trial/status", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["plan"] == "trial"
    assert body["scans_remaining"] == body["scans_limit"]      # nothing used yet


def test_billing_status_reports_trial_access(client, auth):
    r = client.get("/api/billing/status", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["access"] == "trial"
    assert body["trial_days_remaining"] >= 0


def test_status_endpoints_require_auth(client):
    assert client.get("/api/trial/status").status_code == 401
    assert client.get("/api/billing/status").status_code == 401
