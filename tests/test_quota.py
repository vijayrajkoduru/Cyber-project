"""Per-plan scan quota + plan expiry enforcement (audit #2, #5).

Exercises verify_scan_quota directly so we don't depend on any heavy scanner
running — we only care about the gate's accept/deny decision.
"""
import os
import sqlite3
import datetime

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from tools._shared import verify_scan_quota
from tools.auth._db import init_db


def _make_user(user_id, plan="trial", role="user", status="active", expires=None):
    init_db()
    con = sqlite3.connect(os.environ["USERS_DB"])
    con.execute(
        "INSERT OR REPLACE INTO users "
        "(id, username, email, password_hash, role, plan, status, created_at, plan_expires_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (user_id, user_id, f"{user_id}@e.com", "x", role, plan, status,
         datetime.datetime.utcnow().isoformat(), expires))
    con.commit()
    con.close()


def _fake_request():
    # Minimal external (non-internal-fanout) request.
    return Request({"type": "http", "headers": [], "client": ("203.0.113.9", 1234)})


def _payload(user_id, plan="trial", role="user", expires=None):
    return {"sub": user_id, "plan": plan, "role": role, "plan_expires_at": expires}


def test_trial_allows_up_to_daily_limit_then_429():
    _make_user("q_trial", plan="trial")
    req = _fake_request()
    limit = int(os.getenv("QUOTA_TRIAL_PER_DAY", "5"))
    for _ in range(limit):
        verify_scan_quota(req, _payload("q_trial"))         # within limit: ok
    with pytest.raises(HTTPException) as exc:
        verify_scan_quota(req, _payload("q_trial"))         # one over: blocked
    assert exc.value.status_code == 429


def test_admin_is_uncapped():
    _make_user("q_admin", role="admin")
    req = _fake_request()
    for _ in range(50):
        verify_scan_quota(req, _payload("q_admin", role="admin"))  # never raises


def test_unlimited_plan_is_uncapped():
    _make_user("q_ent", plan="enterprise")
    req = _fake_request()
    for _ in range(50):
        verify_scan_quota(req, _payload("q_ent", plan="enterprise"))


def test_expired_plan_is_blocked_402():
    past = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat() + "Z"
    _make_user("q_exp", plan="trial", expires=past)
    with pytest.raises(HTTPException) as exc:
        verify_scan_quota(_fake_request(), _payload("q_exp", expires=past))
    assert exc.value.status_code == 402
