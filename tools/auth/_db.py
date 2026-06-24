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

_SCHEMA_MIGRATED = False


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
            subscription_expires_at TEXT,
            scans_used INTEGER DEFAULT 0,
            usage_period TEXT DEFAULT '',
            modules TEXT DEFAULT '',
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_email ON users(email);

        -- RBAC / Teams (Phase 2.1) -----------------------------------------
        CREATE TABLE IF NOT EXISTS orgs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            plan TEXT DEFAULT 'trial',
            owner_user_id TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS org_members (
            org_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            added_at TEXT NOT NULL,
            invited_by TEXT,
            PRIMARY KEY (org_id, user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_member_user ON org_members(user_id);

        -- Audit log (Phase 2.1) — append-only -----------------------------
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            org_id TEXT,
            actor_id TEXT,
            actor_name TEXT,
            action TEXT NOT NULL,
            target TEXT,
            detail TEXT,
            ip TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id, id);
    """)
    # Migrate pre-existing DBs that lack the billing columns (ALTER throws once
    # the column exists -> caught). Runs once per process.
    global _SCHEMA_MIGRATED
    if not _SCHEMA_MIGRATED:
        for _ddl in (
            "ALTER TABLE users ADD COLUMN subscription_expires_at TEXT",
            "ALTER TABLE users ADD COLUMN scans_used INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN usage_period TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN modules TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN tokens_valid_after TEXT DEFAULT ''",
        ):
            try:
                con.execute(_ddl)
            except Exception:
                pass
        # Backfill (Phase 2.1): every existing user gets a personal org as
        # Owner, so today's single-user behaviour is preserved exactly — orgs
        # can just now hold more members. Idempotent (only users with no org).
        try:
            orphans = con.execute(
                "SELECT u.id, u.username, u.plan, u.created_at FROM users u "
                "WHERE NOT EXISTS (SELECT 1 FROM org_members m WHERE m.user_id = u.id)"
            ).fetchall()
            for uid, uname, uplan, ucreated in orphans:
                # Deterministic personal-org id (uuid5) + INSERT OR IGNORE so two
                # uvicorn workers cold-starting at once converge on ONE org for
                # the user instead of racing to two different uuid4 orgs.
                oid = str(uuid.uuid5(uuid.NAMESPACE_URL, "vulnuslab:personal-org:" + str(uid)))
                ts = ucreated or (datetime.datetime.utcnow().isoformat() + "Z")
                con.execute(
                    "INSERT OR IGNORE INTO orgs (id, name, plan, owner_user_id, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (oid, uname or uid, uplan or "trial", uid, ts))
                con.execute(
                    "INSERT OR IGNORE INTO org_members (org_id, user_id, role, added_at) "
                    "VALUES (?, ?, 'owner', ?)", (oid, uid, ts))
        except Exception:
            pass
        _SCHEMA_MIGRATED = True
    con.commit()
    con.close()
    _seed_admin()


def _seed_admin():
    """Bootstrap the default ADMIN superadmin from .env ADMIN_PASSWORD — but ONLY
    when there is no admin/superadmin yet. Once you have your own admin, the
    default ADMIN can be deleted permanently (it will not be re-created)."""
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    if not admin_password:
        return
    con = sqlite3.connect(DB_PATH)
    try:
        # Bootstrap-only: skip if ANY admin/superadmin already exists.
        row = con.execute(
            "SELECT 1 FROM users WHERE role IN ('admin','superadmin') LIMIT 1"
        ).fetchone()
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
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    # WAL + busy_timeout: readers don't block the writer and concurrent scans
    # wait briefly instead of erroring with "database is locked".
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=5000")
    except Exception:
        pass
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
