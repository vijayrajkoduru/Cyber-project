"""Batch-2 auth hardening: bcrypt length cap (#7) + login throttle (#8)."""


def _register(client, username, password="password123", email=None):
    return client.post("/api/auth/register", json={
        "username": username,
        "email": email or f"{username}@example.com",
        "password": password,
    })


# ── #7: bcrypt 72-byte truncation ───────────────────────────────────
def test_register_rejects_password_over_72_bytes(client):
    r = _register(client, "longpw", password="A" * 73)
    assert r.status_code == 400


def test_register_accepts_72_byte_password(client):
    r = _register(client, "okpw", password="A" * 72)
    assert r.status_code == 200


# ── #8: login brute-force throttle ──────────────────────────────────
def test_login_throttles_after_repeated_attempts(client):
    _register(client, "throttle")
    # default cap is 10 attempts / window; the 11th must be rejected with 429
    saw_429 = False
    for _ in range(15):
        r = client.post("/api/auth/login",
                        json={"username": "throttle", "password": "wrong-password"})
        if r.status_code == 429:
            saw_429 = True
            break
    assert saw_429, "login was never throttled despite repeated failures"
