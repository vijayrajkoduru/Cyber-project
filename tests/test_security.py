"""JWT verification + admin authorization gates (tools/_shared.py)."""
import os
import datetime

from jose import jwt

SECRET = os.environ["JWT_SECRET"]


def _token(**claims):
    payload = {
        "sub": "u1",
        "role": "user",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    }
    payload.update(claims)
    return jwt.encode(payload, SECRET, algorithm="HS256")


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ── verify_token ────────────────────────────────────────────────────
def test_protected_route_requires_authorization_header(client):
    assert client.get("/test/protected").status_code == 401


def test_protected_route_rejects_garbage_token(client):
    assert client.get("/test/protected", headers=_auth("not.a.jwt")).status_code == 401


def test_protected_route_accepts_valid_token(client):
    r = client.get("/test/protected", headers=_auth(_token()))
    assert r.status_code == 200
    assert r.json()["sub"] == "u1"


def test_protected_route_rejects_token_signed_with_wrong_secret(client):
    bad = jwt.encode(
        {"sub": "u1", "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        "the-wrong-secret", algorithm="HS256")
    assert client.get("/test/protected", headers=_auth(bad)).status_code == 401


def test_protected_route_rejects_expired_token(client):
    expired = jwt.encode(
        {"sub": "u1", "exp": datetime.datetime.utcnow() - datetime.timedelta(hours=1)},
        SECRET, algorithm="HS256")
    assert client.get("/test/protected", headers=_auth(expired)).status_code == 401


# ── verify_admin ────────────────────────────────────────────────────
def test_admin_route_forbidden_for_regular_user(client):
    r = client.get("/test/admin-only", headers=_auth(_token(role="user")))
    assert r.status_code == 403


def test_admin_route_allows_admin_role(client):
    r = client.get("/test/admin-only", headers=_auth(_token(role="admin")))
    assert r.status_code == 200


def test_admin_route_allows_superadmin_role(client):
    r = client.get("/test/admin-only", headers=_auth(_token(role="superadmin")))
    assert r.status_code == 200


# ── /api/auth/me round-trip (token issued by register is accepted) ──
def test_me_endpoint_returns_current_user(client):
    reg = client.post("/api/auth/register", json={
        "username": "ivy", "email": "ivy@example.com", "password": "password123"})
    token = reg.json()["access_token"]
    r = client.get("/api/auth/me", headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["username"] == "ivy"


def test_me_endpoint_requires_token(client):
    assert client.get("/api/auth/me").status_code == 401
