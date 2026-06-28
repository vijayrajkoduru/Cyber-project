"""Tests for the platform-hardening layer added in the enterprise-gap pass:
observability, rate limiting, the secret accessor, and the DB factory.

Hermetic: no network, no external binaries, no real DB. Each test stands up a
tiny FastAPI app (or calls the pure helpers directly) so it runs anywhere CI
runs.
"""
import importlib
import os

import pytest

# ── secrets ──────────────────────────────────────────────────────────

def test_get_secret_reads_env(monkeypatch):
    from tools._core import secrets
    monkeypatch.setenv("VL_TEST_SECRET", "hunter2")
    assert secrets.get_secret("VL_TEST_SECRET") == "hunter2"
    assert secrets.get_secret("VL_MISSING", "fallback") == "fallback"
    assert secrets.get_secret("VL_MISSING") is None


def test_require_secret_raises_on_missing(monkeypatch):
    from tools._core import secrets
    monkeypatch.delenv("VL_DEF_MISSING", raising=False)
    with pytest.raises(RuntimeError):
        secrets.require_secret("VL_DEF_MISSING")


def test_require_secret_rejects_placeholder(monkeypatch):
    from tools._core import secrets
    monkeypatch.setenv("VL_PH", "your_actual_key_here")
    with pytest.raises(RuntimeError):
        secrets.require_secret("VL_PH")


def test_audit_placeholders_flags_template_values(monkeypatch):
    from tools._core import secrets
    monkeypatch.setenv("VL_REAL", "sk-live-abc123")
    monkeypatch.setenv("VL_FAKE", "PASTE_NEW_TOKEN_HERE")
    flagged = secrets.audit_placeholders(["VL_REAL", "VL_FAKE", "VL_ABSENT"])
    assert flagged == ["VL_FAKE"]


# ── db factory ───────────────────────────────────────────────────────

def test_db_defaults_to_sqlite(tmp_path):
    # Re-import with DATABASE_URL unset to get the sqlite path.
    os.environ.pop("DATABASE_URL", None)
    import tools._core.db as db
    importlib.reload(db)
    assert db.backend_name() == "sqlite"
    assert db.q("SELECT ?") == "SELECT ?"  # no-op for sqlite
    con = db.get_conn(str(tmp_path / "t.db"))
    con.execute("CREATE TABLE x (a INTEGER)")
    con.execute("INSERT INTO x VALUES (?)", (1,))
    assert con.execute("SELECT a FROM x").fetchone()[0] == 1
    con.close()


def test_db_postgres_paramstyle_translation(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h/db")
    import tools._core.db as db
    importlib.reload(db)
    try:
        assert db.IS_POSTGRES is True
        assert db.backend_name() == "postgres"
        assert db.q("SELECT * FROM t WHERE a = ? AND b = ?") == \
            "SELECT * FROM t WHERE a = %s AND b = %s"
    finally:
        monkeypatch.delenv("DATABASE_URL", raising=False)
        importlib.reload(db)  # restore module-level globals for other tests


# ── observability ────────────────────────────────────────────────────

def _mini_app():
    from fastapi import FastAPI
    from tools._core.observability import install_observability
    app = FastAPI()
    install_observability(app)

    @app.get("/api/ping")
    async def ping():
        return {"ok": True}
    return app


def test_metrics_endpoint_and_request_id():
    from starlette.testclient import TestClient
    c = TestClient(_mini_app())
    r = c.get("/api/ping")
    assert r.status_code == 200
    assert "x-request-id" in {k.lower() for k in r.headers}
    m = c.get("/api/metrics")
    assert m.status_code == 200
    assert "vl_http_requests_total" in m.text
    assert "vl_http_request_duration_seconds" in m.text
    assert "vl_process_uptime_seconds" in m.text


def test_request_id_is_echoed_when_supplied():
    from starlette.testclient import TestClient
    c = TestClient(_mini_app())
    r = c.get("/api/ping", headers={"X-Request-ID": "trace-abc"})
    assert r.headers["x-request-id"] == "trace-abc"


# ── rate limiting ────────────────────────────────────────────────────

def test_rate_limit_blocks_after_threshold(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "3")
    import tools._core.ratelimit as rl
    importlib.reload(rl)
    from fastapi import FastAPI
    from starlette.testclient import TestClient
    app = FastAPI()
    rl.install_rate_limit(app)

    @app.get("/api/work")
    async def work():
        return {"ok": True}

    c = TestClient(app)
    codes = [c.get("/api/work").status_code for _ in range(5)]
    assert codes.count(200) == 3
    assert codes.count(429) == 2
    # exempt paths are never limited
    app2_ok = c.get("/api/work")
    assert app2_ok.status_code == 429
    assert "Retry-After" in app2_ok.headers


def test_rate_limit_can_be_disabled(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "0")
    import tools._core.ratelimit as rl
    importlib.reload(rl)
    from fastapi import FastAPI
    from starlette.testclient import TestClient
    app = FastAPI()
    rl.install_rate_limit(app)

    @app.get("/api/work")
    async def work():
        return {"ok": True}

    c = TestClient(app)
    codes = [c.get("/api/work").status_code for _ in range(10)]
    assert all(code == 200 for code in codes)
