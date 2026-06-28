"""Enterprise Phase 2 — email verification + MFA/TOTP.

Requires Postgres (DATABASE_URL); skips cleanly otherwise. See
test_enterprise_phase1.py for how to run against a throwaway Postgres.
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
    with db.get_db() as con:
        con.execute(
            "INSERT INTO users (id, username, email, password_hash, role, plan, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (uid, "p2_" + uid[:8], f"p2{uid[:8]}@x.com", db.hash_password("pw"),
             "user", "trial", "active", datetime.datetime.utcnow().isoformat() + "Z"),
        )
    return uid


def test_email_verification_flow(user_id):
    assert db.is_email_verified(user_id) is False
    tok = db.create_email_token(user_id, "verify")
    assert db.consume_email_token("bogus", "verify") is None
    assert db.consume_email_token(tok, "verify") == user_id
    db.mark_email_verified(user_id)
    assert db.is_email_verified(user_id) is True
    assert db.consume_email_token(tok, "verify") is None  # single-use


def test_mfa_totp_flow(user_id):
    pyotp = pytest.importorskip("pyotp")
    secret = pyotp.random_base32()
    db.set_mfa_secret(user_id, secret)
    assert db.get_mfa(user_id) == {"enabled": False, "secret": secret}
    db.enable_mfa(user_id)
    assert db.get_mfa(user_id)["enabled"] is True
    # the exact check login.py performs
    assert pyotp.TOTP(secret).verify(pyotp.TOTP(secret).now(), valid_window=1)
    db.disable_mfa(user_id)
    assert db.get_mfa(user_id) == {"enabled": False, "secret": None}


def test_email_sender_graceful(monkeypatch):
    monkeypatch.delenv("EMAIL_API_KEY", raising=False)
    from tools._core.email_send import send_email
    assert send_email("a@b.com", "s", "<p>x</p>") is False  # no raise, returns False
