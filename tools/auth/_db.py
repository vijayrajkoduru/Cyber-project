"""SQLite user database — schema + admin seed.

Underscore-prefixed file so main.py's tool autoloader skips it.
Other auth tools import from here.
"""
import os
import uuid
import sqlite3
import datetime
from contextlib import contextmanager
from pathlib import Path

from passlib.context import CryptContext

DB_PATH = Path(os.getenv("USERS_DB", "/app/data/users.db"))

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _ensure_dir():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def init_db():
    """Create the users table if it doesn't exist. Seeds an ADMIN user
    on first run using ADMIN_PASSWORD from .env."""
    _ensure_dir()
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            plan TEXT DEFAULT 'trial',
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_email ON users(email);
    """)
    con.commit()
    con.close()
    _seed_admin()


def _seed_admin():
    """Create the ADMIN superadmin user from .env ADMIN_PASSWORD."""
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    if not admin_password:
        return
    con = sqlite3.connect(DB_PATH)
    try:
        row = con.execute("SELECT 1 FROM users WHERE username=?", ("ADMIN",)).fetchone()
        if row:
            return
        hashed = _pwd_ctx.hash(admin_password)
        now = datetime.datetime.utcnow().isoformat() + "Z"
        con.execute(
            "INSERT INTO users (id, username, email, password_hash, role, plan, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), "ADMIN", "admin@vulnuslab.com", hashed,
             "superadmin", "superadmin", "active", now),
        )
        con.commit()
    finally:
        con.close()


@contextmanager
def get_db():
    """Context manager for SQLite connection. Auto-inits schema on first call."""
    init_db()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _pwd_ctx.verify(plain, hashed)
    except Exception:
        return False
