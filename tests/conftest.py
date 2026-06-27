"""Shared pytest fixtures + hermetic test environment.

CRITICAL: the required env vars are set at *import time*, before any
application module is imported. main.py and tools/_shared.py read
JWT_SECRET at import and refuse to load without it; tools/auth/_db.py
reads USERS_DB at import to locate the SQLite file. Setting them here
(conftest is imported first by pytest) keeps the whole suite hermetic —
no real database, no /app or /data writes.
"""
import os
import tempfile
import pathlib

# ── Hermetic environment (must run before app imports) ──────────────
_TMP = tempfile.mkdtemp(prefix="vl-tests-")
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-production")
os.environ["USERS_DB"] = os.path.join(_TMP, "users.db")
os.environ.setdefault("ADMIN_PASSWORD", "")          # skip admin seeding
os.environ.setdefault("CORS_ORIGINS", "*")

# Redirect the per-user data zone (hardcoded to /data/users in source)
# into the temp dir so register/login can't touch the real filesystem.
try:
    from tools._core import userzone as _uz
    _uz.DATA_ROOT = pathlib.Path(_TMP) / "users"
except Exception:
    pass

import sqlite3
import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def app():
    """A lightweight app with just the auth routers plus two test-only
    routes that exercise the security dependencies in isolation — no
    full 1,476-module boot, so auth tests stay fast and deterministic."""
    from tools.auth import register as register_mod
    from tools.auth import login as login_mod
    from tools.auth import me as me_mod
    from tools._shared import verify_token, verify_admin

    a = FastAPI()
    register_mod.register(a)
    login_mod.register(a)
    me_mod.register(a)

    @a.get("/test/protected")
    def _protected(payload=Depends(verify_token)):
        return {"sub": payload.get("sub")}

    @a.get("/test/admin-only")
    def _admin_only(payload=Depends(verify_admin)):
        return {"ok": True, "role": payload.get("role")}

    return a


@pytest.fixture()
def client(app):
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clean_users_table():
    """Wipe the users table before each test for isolation. The table may
    not exist yet on the first call — that's fine."""
    def _wipe():
        try:
            con = sqlite3.connect(os.environ["USERS_DB"])
            con.execute("DELETE FROM users")
            con.commit()
            con.close()
        except Exception:
            pass
    _wipe()
    yield
    _wipe()
