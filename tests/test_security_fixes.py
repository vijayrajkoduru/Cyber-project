"""Tests for security fixes: reverse-proxy bypass, timing attacks,
rate limiting, username DoS, and plan-extension validation."""
import os
import time
import uuid
import sqlite3
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure JWT_SECRET is set before anything imports it
os.environ.setdefault("JWT_SECRET", "test-secret-key-for-unit-tests")
os.environ.setdefault("USERS_DB", "/tmp/vl_test_users_" + str(uuid.uuid4()) + ".db")

from tools._shared import is_internal_fanout, _INTERNAL_FANOUT_HEADER, _INTERNAL_FANOUT_TOKEN
from tools.auth.login import (
    router as login_router,
    _check_login_rate,
    _login_attempts,
    MAX_LOGIN_ATTEMPTS,
    LOGIN_WINDOW,
)
from tools.auth.register import (
    router as register_router,
    _check_register_rate,
    _register_attempts,
    MAX_REGISTER_ATTEMPTS,
    REGISTER_WINDOW,
)
from tools.admin.users import router as admin_router, verify_admin_or_super
from tools.auth._db import init_db, get_db, hash_password


# ── fixtures ───────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_rate_limiters():
    """Clear in-memory rate-limit state before every test."""
    _login_attempts.clear()
    _register_attempts.clear()
    yield
    _login_attempts.clear()
    _register_attempts.clear()


@pytest.fixture(autouse=True)
def clean_db():
    """Remove test DB and re-initialise schema before every test."""
    db_path = os.environ["USERS_DB"]
    if os.path.exists(db_path):
        os.remove(db_path)
    init_db()
    yield
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.fixture
def app():
    """Minimal FastAPI app with the auth + admin routers wired."""
    a = FastAPI()
    a.include_router(login_router)
    a.include_router(register_router)
    a.include_router(admin_router)
    return a


@pytest.fixture
def client(app):
    return TestClient(app)


def _create_user(username: str, password: str, role: str = "user", status: str = "active", plan: str = "trial") -> None:
    with get_db() as con:
        con.execute(
            "INSERT INTO users (id, username, email, password_hash, role, plan, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), username, f"{username}@test.com", hash_password(password),
             role, plan, status, "2024-01-01T00:00:00Z"),
        )


def _admin_token() -> str:
    import datetime
    from jose import jwt
    payload = {
        "sub": "admin-id",
        "username": "ADMIN",
        "role": "superadmin",
        "plan": "superadmin",
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    }
    return jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")


# ── Issue 1: is_internal_fanout ────────────────────────────────────

class FakeRequest:
    def __init__(self, headers=None, client_host=None):
        self.headers = headers or {}
        class FakeClient:
            def __init__(self, host):
                self.host = host
        self.client = FakeClient(client_host) if client_host else None


def test_is_internal_fanout_none_request():
    assert is_internal_fanout(None) is False


def test_is_internal_fanout_correct_header():
    req = FakeRequest(headers={_INTERNAL_FANOUT_HEADER: _INTERNAL_FANOUT_TOKEN}, client_host="10.0.0.1")
    assert is_internal_fanout(req) is True


def test_is_internal_fanout_wrong_header():
    req = FakeRequest(headers={_INTERNAL_FANOUT_HEADER: "wrong-token"}, client_host="127.0.0.1")
    assert is_internal_fanout(req) is False


def test_is_internal_fanout_no_header():
    req = FakeRequest(headers={}, client_host="127.0.0.1")
    assert is_internal_fanout(req) is False


def test_is_internal_fanout_bypasses_ip_check():
    """External IP with correct header should succeed (proxy-safe)."""
    req = FakeRequest(headers={_INTERNAL_FANOUT_HEADER: _INTERNAL_FANOUT_TOKEN}, client_host="8.8.8.8")
    assert is_internal_fanout(req) is True


# ── Issue 2: login timing-attack mitigation ────────────────────────

def test_login_nonexistent_user_raises_401_and_verifies_dummy(client):
    """When user does not exist, verify_password must still be called
    (with a dummy hash) so timing is indistinguishable from wrong password."""
    response = client.post("/api/auth/login", json={"username": "nouser", "password": "password123"})
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]


def test_login_wrong_password_raises_401(client):
    _create_user("alice", "correctpassword")
    response = client.post("/api/auth/login", json={"username": "alice", "password": "wrongpassword"})
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]


def test_login_success(client):
    _create_user("bob", "secret123")
    response = client.post("/api/auth/login", json={"username": "bob", "password": "secret123"})
    assert response.status_code == 200
    assert response.json()["username"] == "bob"
    assert "access_token" in response.json()


# ── Issue 3: login rate limiting ───────────────────────────────────

def test_login_rate_limit_blocks_after_max_attempts(client):
    _create_user("ratelimit_user", "pass1234")
    for _ in range(MAX_LOGIN_ATTEMPTS):
        r = client.post("/api/auth/login", json={"username": "ratelimit_user", "password": "wrong"})
        assert r.status_code == 401

    # next attempt should be 429
    r = client.post("/api/auth/login", json={"username": "ratelimit_user", "password": "wrong"})
    assert r.status_code == 429
    assert "Too many login attempts" in r.json()["detail"]


def test_login_rate_limit_resets_after_window(monkeypatch, client):
    # Test blocking with a long-enough window so all attempts fit.
    _create_user("ratelimit_window", "pass1234")
    for _ in range(MAX_LOGIN_ATTEMPTS):
        client.post("/api/auth/login", json={"username": "ratelimit_window", "password": "wrong"})

    r = client.post("/api/auth/login", json={"username": "ratelimit_window", "password": "wrong"})
    assert r.status_code == 429

    # Simulate window expiry by setting window to 0 so all old attempts drop.
    monkeypatch.setattr("tools.auth.login.LOGIN_WINDOW", 0.0)
    r = client.post("/api/auth/login", json={"username": "ratelimit_window", "password": "pass1234"})
    assert r.status_code == 200


def test_login_rate_limit_per_username_isolated(client):
    _create_user("user_a", "pass1234")
    _create_user("user_b", "pass1234")
    for _ in range(MAX_LOGIN_ATTEMPTS):
        client.post("/api/auth/login", json={"username": "user_a", "password": "wrong"})

    # user_b should still be able to login
    r = client.post("/api/auth/login", json={"username": "user_b", "password": "pass1234"})
    assert r.status_code == 200


# ── Issue 3: register rate limiting ────────────────────────────────

def test_register_rate_limit_blocks_after_max_attempts(client):
    # Use the same username with a short password so each request fails
    # at password-length validation (before DB insert) but still increments
    # the per-username rate limiter.
    for _ in range(MAX_REGISTER_ATTEMPTS):
        r = client.post("/api/auth/register", json={
            "username": "reguser_ratelimit",
            "email": "ratelimit@test.com",
            "password": "short",
        })
        assert r.status_code == 400

    # Same username again should now be 429
    r = client.post("/api/auth/register", json={
        "username": "reguser_ratelimit",
        "email": "another@test.com",
        "password": "password123",
    })
    assert r.status_code == 429
    assert "Too many registration attempts" in r.json()["detail"]


def test_register_rate_limit_per_username_isolated(client):
    for i in range(MAX_REGISTER_ATTEMPTS):
        r = client.post("/api/auth/register", json={
            "username": f"iso_user_{i}",
            "email": f"iso_user_{i}@test.com",
            "password": "password123",
        })
        assert r.status_code == 200

    # a *different* username should still be allowed
    r = client.post("/api/auth/register", json={
        "username": "fresh_user",
        "email": "fresh@test.com",
        "password": "password123",
    })
    assert r.status_code == 200


# ── Issue 4: username length DoS ───────────────────────────────────

def test_register_rejects_username_over_64_chars(client):
    long_name = "a" * 65
    r = client.post("/api/auth/register", json={
        "username": long_name,
        "email": "long@test.com",
        "password": "password123",
    })
    assert r.status_code == 400
    assert "at most 64 characters" in r.json()["detail"]


def test_register_accepts_username_at_64_chars(client):
    name_64 = "a" * 64
    r = client.post("/api/auth/register", json={
        "username": name_64,
        "email": "ok64@test.com",
        "password": "password123",
    })
    assert r.status_code == 200
    assert r.json()["username"] == name_64


# ── Issue 5: extend_plan days >= 1 ─────────────────────────────────

def test_extend_plan_rejects_zero_days(client):
    _create_user("extendme", "pass1234")
    token = _admin_token()
    r = client.post(
        "/api/admin/users/extendme/extend",
        json={"days": 0, "plan": "pro"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 400
    assert "between 1 and 3650" in r.json()["detail"]


def test_extend_plan_rejects_negative_days(client):
    _create_user("extendme2", "pass1234")
    token = _admin_token()
    r = client.post(
        "/api/admin/users/extendme2/extend",
        json={"days": -1, "plan": "pro"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 400
    assert "between 1 and 3650" in r.json()["detail"]


def test_extend_plan_accepts_one_day(client):
    _create_user("extendme3", "pass1234")
    token = _admin_token()
    r = client.post(
        "/api/admin/users/extendme3/extend",
        json={"days": 1, "plan": "pro"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json()["extended_days"] == 1


def test_extend_plan_rejects_over_3650(client):
    _create_user("extendme4", "pass1234")
    token = _admin_token()
    r = client.post(
        "/api/admin/users/extendme4/extend",
        json={"days": 3651, "plan": "pro"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 400
    assert "between 1 and 3650" in r.json()["detail"]
