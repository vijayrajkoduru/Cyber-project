"""Enterprise Phase 3 — organizations + RBAC. Requires Postgres; skips otherwise."""
import datetime
import os
import uuid

import pytest

if not os.getenv("DATABASE_URL", "").startswith(("postgres://", "postgresql")):
    pytest.skip("DATABASE_URL (Postgres) not set", allow_module_level=True)

import tools.auth._db as db  # noqa: E402


def _mkuser(tag):
    db.init_db()
    uid = str(uuid.uuid4())
    with db.get_db() as con:
        con.execute(
            "INSERT INTO users (id, username, email, password_hash, role, plan, status, created_at) "
            "VALUES (?, ?, ?, ?, 'user', 'trial', 'active', ?)",
            (uid, tag + uid[:6], f"{tag}{uid[:6]}@x.com", db.hash_password("pw"),
             datetime.datetime.utcnow().isoformat() + "Z"))
    return uid


def test_org_rbac_lifecycle():
    owner, alice, bob = _mkuser("o"), _mkuser("a"), _mkuser("b")
    org = db.create_org("Acme", owner)
    oid = org["id"]
    assert db.get_member_role(oid, owner) == "owner"
    assert db.has_org_role(oid, owner, "admin") is True
    assert db.has_org_role(oid, alice, "member") is False

    db.add_org_member(oid, alice, "admin")
    db.add_org_member(oid, bob, "member")
    assert db.has_org_role(oid, alice, "admin") is True
    assert db.has_org_role(oid, bob, "admin") is False
    assert db.has_org_role(oid, bob, "member") is True

    assert len(db.list_org_members(oid)) == 3
    assert db.set_member_role(oid, bob, "admin") is True
    assert db.has_org_role(oid, bob, "admin") is True

    # owner cannot be removed; ordinary members can
    assert db.remove_org_member(oid, owner) is False
    assert db.remove_org_member(oid, bob) is True
    assert db.get_member_role(oid, bob) is None


def test_list_user_orgs_and_find_email():
    owner = _mkuser("u")
    org = db.create_org("Org-X", owner)
    orgs = db.list_user_orgs(owner)
    assert any(o["id"] == org["id"] and o["role"] == "owner" for o in orgs)
    found = db.find_user_by_email(f"u{owner[:6]}@x.com")
    assert found and found["id"] == owner


def _token(uid):
    """Mint a JWT the org endpoints accept (verify_token re-validates the row)."""
    import datetime as _dt
    from jose import jwt
    return jwt.encode(
        {"sub": uid, "role": "user", "plan": "trial",
         "exp": _dt.datetime.utcnow() + _dt.timedelta(hours=1)},
        os.environ["JWT_SECRET"], algorithm="HS256")


def _org_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from tools.org import org_api
    app = FastAPI()
    org_api.register(app)
    return TestClient(app)


def test_change_role_endpoint_rejects_owner_escalation():
    """An org ADMIN must not be able to self-promote (or promote anyone) to
    'owner' via PATCH /members/{uid} — regression for the RBAC privilege-
    escalation bug (change_role previously allowed req.role == 'owner')."""
    owner, admin, victim = _mkuser("o"), _mkuser("a"), _mkuser("v")
    org = db.create_org("EscTest", owner)
    oid = org["id"]
    db.add_org_member(oid, admin, "admin")
    db.add_org_member(oid, victim, "member")

    client = _org_client()
    hdr = {"Authorization": f"Bearer {_token(admin)}"}

    # admin tries to self-promote to owner -> must be rejected
    r = client.patch(f"/api/orgs/{oid}/members/{admin}", json={"role": "owner"}, headers=hdr)
    assert r.status_code == 400, r.text
    assert db.get_member_role(oid, admin) == "admin"

    # admin tries to promote another member to owner -> must be rejected
    r = client.patch(f"/api/orgs/{oid}/members/{victim}", json={"role": "owner"}, headers=hdr)
    assert r.status_code == 400, r.text
    assert db.get_member_role(oid, victim) == "member"

    # a legitimate member<->admin change still works
    r = client.patch(f"/api/orgs/{oid}/members/{victim}", json={"role": "admin"}, headers=hdr)
    assert r.status_code == 200, r.text
    assert db.get_member_role(oid, victim) == "admin"
