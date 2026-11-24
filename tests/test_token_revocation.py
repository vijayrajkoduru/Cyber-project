"""Server-side JWT revocation via users.token_version (TOKEN-REVOKE-V1).

Runs only against the hermetic test DB (see conftest.py) -- NEVER against
the live backend container / prod DATABASE_URL.
"""
import os
import datetime

from jose import jwt

SECRET = os.environ["JWT_SECRET"]


def _register(client, username):
    r = client.post("/api/auth/register", json={
        "username": username, "email": f"{username}@example.com",
        "password": "password123"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auth(tok):
    return {"Authorization": f"Bearer {tok}"}


def _sub(tok):
    return jwt.get_unverified_claims(tok)["sub"]


def test_new_tokens_carry_ver_jti_iat(client):
    claims = jwt.get_unverified_claims(_register(client, "rv_claims"))
    assert claims["ver"] == 0
    assert claims["jti"] and claims["iat"]


def test_legacy_token_without_ver_still_accepted(client):
    sub = _sub(_register(client, "rv_legacy"))
    legacy = jwt.encode({"sub": sub, "exp": datetime.datetime.utcnow()
                         + datetime.timedelta(hours=1)}, SECRET, algorithm="HS256")
    assert client.get("/test/protected", headers=_auth(legacy)).status_code == 200


def test_logout_revokes_all_sessions(client):
    tok = _register(client, "rv_logout")
    other = client.post("/api/auth/login", json={
        "username": "rv_logout", "password": "password123"}).json()["access_token"]
    r = client.post("/api/auth/logout", headers=_auth(tok))
    assert r.status_code == 200 and r.json()["revoked"] is True
    assert client.get("/test/protected", headers=_auth(tok)).status_code == 401
    assert client.get("/test/protected", headers=_auth(other)).status_code == 401
    # A revoked token cannot trigger another log-out-everywhere.
    fresh = client.post("/api/auth/login", json={
        "username": "rv_logout", "password": "password123"}).json()["access_token"]
    assert client.post("/api/auth/logout", headers=_auth(tok)).json()["revoked"] is False
    assert client.get("/test/protected", headers=_auth(fresh)).status_code == 200


def test_password_change_revokes(client):
    from tools.auth._db import set_user_password
    tok = _register(client, "rv_pw")
    assert set_user_password(_sub(tok), "newpassword123")
    assert client.get("/test/protected", headers=_auth(tok)).status_code == 401


def test_plan_demotion_revokes_but_upgrade_does_not(client):
    from tools.admin.users import _set_plan
    tok = _register(client, "rv_plan")          # trial
    _set_plan("rv_plan", "pro", None)            # upgrade
    assert client.get("/test/protected", headers=_auth(tok)).status_code == 200
    _set_plan("rv_plan", "trial", None)          # demotion
    assert client.get("/test/protected", headers=_auth(tok)).status_code == 401
