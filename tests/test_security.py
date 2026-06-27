"""JWT verification + DB re-validation + admin gates (audit #4)."""
import os
import sqlite3
import datetime

from jose import jwt

SECRET = os.environ["JWT_SECRET"]


def _register_token(client, username, password="password123"):
    r = client.post("/api/auth/register", json={
        "username": username, "email": f"{username}@example.com", "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _db_update(username, **cols):
    con = sqlite3.connect(os.environ["USERS_DB"])
    for k, v in cols.items():
        con.execute(f"UPDATE users SET {k}=? WHERE username=?", (v, username))
    con.commit()
    con.close()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _forged(**claims):
    payload = {"sub": "nobody", "role": "user",
               "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
    payload.update(claims)
    return jwt.encode(payload, SECRET, algorithm="HS256")


# ── verify_token: token validity ────────────────────────────────────
def test_protected_route_requires_authorization_header(client):
    assert client.get("/test/protected").status_code == 401


def test_protected_route_rejects_garbage_token(client):
    assert client.get("/test/protected", headers=_auth("not.a.jwt")).status_code == 401


def test_protected_route_rejects_wrong_secret(client):
    bad = jwt.encode({"sub": "x", "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                     "the-wrong-secret", algorithm="HS256")
    assert client.get("/test/protected", headers=_auth(bad)).status_code == 401


def test_protected_route_rejects_expired_token(client):
    expired = jwt.encode({"sub": "x", "exp": datetime.datetime.utcnow() - datetime.timedelta(hours=1)},
                         SECRET, algorithm="HS256")
    assert client.get("/test/protected", headers=_auth(expired)).status_code == 401


def test_protected_route_accepts_real_user_token(client):
    tok = _register_token(client, "alice")
    r = client.get("/test/protected", headers=_auth(tok))
    assert r.status_code == 200
    assert r.json()["sub"]


# ── verify_token: DB re-validation (audit #4) ───────────────────────
def test_token_for_nonexistent_user_rejected(client):
    # validly signed, but the sub was never in the DB
    assert client.get("/test/protected", headers=_auth(_forged())).status_code == 401


def test_token_rejected_after_user_suspended(client):
    tok = _register_token(client, "bob")
    assert client.get("/test/protected", headers=_auth(tok)).status_code == 200
    _db_update("bob", status="suspended")
    assert client.get("/test/protected", headers=_auth(tok)).status_code == 403


def test_role_demotion_takes_effect_immediately(client):
    tok = _register_token(client, "carol")
    _db_update("carol", role="admin")
    assert client.get("/test/admin-only", headers=_auth(tok)).status_code == 200
    _db_update("carol", role="user")           # demote
    assert client.get("/test/admin-only", headers=_auth(tok)).status_code == 403


# ── verify_admin ────────────────────────────────────────────────────
def test_admin_route_forbidden_for_regular_user(client):
    tok = _register_token(client, "dave")
    assert client.get("/test/admin-only", headers=_auth(tok)).status_code == 403


def test_admin_route_allows_admin_role(client):
    tok = _register_token(client, "erin")
    _db_update("erin", role="admin")
    assert client.get("/test/admin-only", headers=_auth(tok)).status_code == 200


# ── /api/auth/me ────────────────────────────────────────────────────
def test_me_endpoint_returns_current_user(client):
    tok = _register_token(client, "frank")
    r = client.get("/api/auth/me", headers=_auth(tok))
    assert r.status_code == 200
    assert r.json()["username"] == "frank"


def test_me_endpoint_requires_token(client):
    assert client.get("/api/auth/me").status_code == 401
