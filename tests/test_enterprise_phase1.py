"""Enterprise Phase 1 — audit log + API keys + API-key auth.

Requires a reachable PostgreSQL via DATABASE_URL (main's auth layer is
Postgres-only). Skips cleanly when it isn't set, so CI without a DB stays
green; run locally/in staging against a throwaway Postgres:

    docker run -d --name pg -e POSTGRES_USER=t -e POSTGRES_PASSWORD=t \
      -e POSTGRES_DB=t -p 5432:5432 postgres:16
    DATABASE_URL=postgresql+psycopg2://t:t@localhost:5432/t \
      JWT_SECRET=test python -m pytest tests/test_enterprise_phase1.py -q
"""
import datetime
import os
import uuid

import pytest

if not os.getenv("DATABASE_URL", "").startswith(("postgres://", "postgresql")):
    pytest.skip("DATABASE_URL (Postgres) not set", allow_module_level=True)

import tools.auth._db as db  # noqa: E402


@pytest.fixture()
def user_id():
    db.init_db()
    uid = str(uuid.uuid4())
    uname = "t_" + uid[:8]
    with db.get_db() as con:
        con.execute(
            "INSERT INTO users (id, username, email, password_hash, role, plan, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (uid, uname, f"{uname}@x.com", db.hash_password("pw"), "user", "pro",
             "active", datetime.datetime.utcnow().isoformat() + "Z"),
        )
    return uid


def test_api_key_lifecycle(user_id):
    secret, meta = db.create_api_key(user_id, "ci")
    assert secret.startswith("vlk_") and meta["prefix"] in secret
    row = db.resolve_api_key(secret)
    assert row and row["id"] == user_id
    # no secret/hash leaked in listing
    keys = db.list_api_keys(user_id)
    assert keys and "key_hash" not in keys[0]
    # revoke kills it
    assert db.revoke_api_key(user_id, meta["id"]) is True
    assert db.resolve_api_key(secret) is None
    assert db.revoke_api_key(user_id, meta["id"]) is False


def test_bad_api_keys_rejected(user_id):
    assert db.resolve_api_key("vlk_deadbeef_nope") is None
    assert db.resolve_api_key("garbage") is None
    assert db.resolve_api_key("") is None


def test_audit_record_filter(user_id):
    db.record_audit("auth.login", actor_id=user_id, actor_name="t", ip="1.2.3.4")
    db.record_audit("auth.login_failed", actor_name="m", ip="9.9.9.9", status="fail")
    page = db.list_audit(limit=50)
    assert page["total"] >= 2
    only_fail = db.list_audit(action="auth.login_failed")
    assert only_fail["items"] and all(r["action"] == "auth.login_failed" for r in only_fail["items"])


def test_verify_token_accepts_api_key(user_id, monkeypatch):
    monkeypatch.setenv("VL_AUTH_CACHE_TTL", "0")
    secret, _ = db.create_api_key(user_id, "k")
    import tools._shared as sh

    class _Creds:
        credentials = secret

    payload = sh.verify_token(_Creds())
    assert payload["sub"] == user_id
    assert payload["auth"] == "api_key"
    assert payload["plan"] == "pro"
