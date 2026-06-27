"""Anti-LFI middleware: binary-analysis scanners must reject targets that
resolve outside the allowed upload/cache dirs (audit finding #1)."""
import pytest
from fastapi.testclient import TestClient

# A real registered bof scanner endpoint that takes a file-path target.
SCANNER = "/api/bof/binary_protection_audit"


@pytest.fixture(scope="module")
def client():
    import main
    return TestClient(main.app)


@pytest.fixture()
def auth(client):
    # Real DB-backed user (verify_token now re-validates against the DB).
    r = client.post("/api/auth/register", json={
        "username": "guarduser", "email": "guard@example.com", "password": "password123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _auth():  # back-compat shim for existing call sites
    raise RuntimeError("use the `auth` fixture")


def test_guard_blocks_absolute_path_traversal(client, auth):
    r = client.post(SCANNER, json={"target": "/etc/passwd"}, headers=auth)
    assert r.status_code == 400
    assert "uploaded" in r.json()["detail"].lower()


def test_guard_blocks_sensitive_app_file(client, auth):
    r = client.post(SCANNER, json={"target": "/app/data/users.db"}, headers=auth)
    assert r.status_code == 400


def test_guard_allows_contained_path_and_preserves_body(client, auth):
    # Stage a file inside an allowed artifact root.
    from tools._shared import artifact_roots
    root = artifact_roots()[0]
    root.mkdir(parents=True, exist_ok=True)
    sample = root / "deadbeef_sample.bin"
    sample.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)

    r = client.post(SCANNER, json={"target": str(sample)}, headers=auth)
    # The guard must NOT block it, and the body must survive the middleware
    # (a 422 'field required' would mean the consumed body was lost).
    assert r.status_code != 422, "request body was eaten by the guard middleware"
    blocked = r.status_code == 400 and "uploaded" in r.json().get("detail", "").lower()
    assert not blocked, "contained path was wrongly blocked"
