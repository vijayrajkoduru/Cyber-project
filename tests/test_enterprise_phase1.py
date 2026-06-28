"""Enterprise Phase 1 — audit log.

(The API-key feature was removed per product decision; this now covers the
audit log only.) Requires Postgres via DATABASE_URL; skips cleanly otherwise.
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


def test_audit_record_filter(user_id):
    db.record_audit("auth.login", actor_id=user_id, actor_name="t", ip="1.2.3.4")
    db.record_audit("auth.login_failed", actor_name="m", ip="9.9.9.9", status="fail")
    page = db.list_audit(limit=50)
    assert page["total"] >= 2
    only_fail = db.list_audit(action="auth.login_failed")
    assert only_fail["items"] and all(r["action"] == "auth.login_failed" for r in only_fail["items"])
