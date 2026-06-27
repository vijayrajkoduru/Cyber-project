"""Auth flow: registration + login (the security-critical happy + sad paths)."""


def _register(client, username="alice", email=None, password="password123"):
    return client.post("/api/auth/register", json={
        "username": username,
        "email": email or f"{username}@example.com",
        "password": password,
    })


# ── Registration ────────────────────────────────────────────────────
def test_register_success_returns_token_and_trial_plan(client):
    r = _register(client)
    assert r.status_code == 200
    d = r.json()
    assert d["access_token"]
    assert d["role"] == "user"
    assert d["plan"] == "trial"
    assert d["user"]["username"] == "alice"
    assert d["user"]["email"] == "alice@example.com"


def test_register_rejects_short_username(client):
    assert _register(client, username="ab").status_code == 400


def test_register_rejects_invalid_username_chars(client):
    assert _register(client, username="bad user!").status_code == 400


def test_register_rejects_bad_email(client):
    r = client.post("/api/auth/register", json={
        "username": "bob", "email": "not-an-email", "password": "password123"})
    assert r.status_code == 400


def test_register_rejects_short_password(client):
    assert _register(client, username="carol", password="short").status_code == 400


def test_register_duplicate_username_conflicts(client):
    assert _register(client, username="dave").status_code == 200
    r = client.post("/api/auth/register", json={
        "username": "dave", "email": "dave2@example.com", "password": "password123"})
    assert r.status_code == 409


def test_register_duplicate_email_conflicts(client):
    assert _register(client, username="erin", email="dup@example.com").status_code == 200
    r = client.post("/api/auth/register", json={
        "username": "erin2", "email": "dup@example.com", "password": "password123"})
    assert r.status_code == 409


# ── Login ───────────────────────────────────────────────────────────
def test_login_success(client):
    _register(client, username="frank")
    r = client.post("/api/auth/login",
                    json={"username": "frank", "password": "password123"})
    assert r.status_code == 200
    assert r.json()["access_token"]


def test_login_is_username_case_insensitive(client):
    _register(client, username="Gina")
    r = client.post("/api/auth/login",
                    json={"username": "gina", "password": "password123"})
    assert r.status_code == 200


def test_login_wrong_password_rejected(client):
    _register(client, username="harry")
    r = client.post("/api/auth/login",
                    json={"username": "harry", "password": "wrong-password"})
    assert r.status_code == 401


def test_login_unknown_user_rejected(client):
    r = client.post("/api/auth/login",
                    json={"username": "ghost", "password": "password123"})
    assert r.status_code == 401
