"""PostgreSQL user database — engine, schema, admin seed, query helpers.

Underscore-prefixed file so main.py's tool autoloader skips it.
Other auth tools import from here.

Backed by SQLAlchemy + psycopg2 with a pooled engine (DATABASE_URL). A thin
compatibility wrapper lets the rest of the codebase keep using the original
sqlite-style API — `con.execute("... ?", (a, b)).fetchone()`, `row["col"]`,
`result.rowcount` — so the auth/admin endpoints didn't need rewriting for
the SQLite->Postgres cutover.
"""
import os
import uuid
import datetime
from contextlib import contextmanager

from passlib.context import CryptContext
from sqlalchemy import create_engine, text

# Postgres is required (full cutover). Format:
#   postgresql+psycopg2://user:pass@host:5432/dbname
DATABASE_URL = os.getenv("DATABASE_URL", "")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL env var is required (PostgreSQL), e.g. "
        "postgresql+psycopg2://user:pass@host:5432/vulnuslab"
    )

_engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,     # drop dead connections instead of erroring
    pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
    max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
    pool_recycle=1800,
    future=True,
)

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── sqlite-style compatibility shim over a SQLAlchemy connection ─────
def _to_named(sql: str, params):
    """Convert positional '?' placeholders to SQLAlchemy ':pN' bind params."""
    if not params:
        return sql, {}
    out, binds, i = [], {}, 0
    for ch in sql:
        if ch == "?":
            key = f"p{i}"
            out.append(f":{key}")
            binds[key] = params[i]
            i += 1
        else:
            out.append(ch)
    return "".join(out), binds


class _Result:
    def __init__(self, cursor_result):
        self._cr = cursor_result

    @property
    def rowcount(self):
        return self._cr.rowcount

    def fetchone(self):
        row = self._cr.mappings().fetchone()
        return dict(row) if row is not None else None

    def fetchall(self):
        return [dict(r) for r in self._cr.mappings().fetchall()]


class _Conn:
    def __init__(self, conn):
        self._c = conn

    def execute(self, sql, params=None):
        s, binds = _to_named(sql, params or ())
        return _Result(self._c.execute(text(s), binds))


# ── Schema + seed (idempotent, guarded) ─────────────────────────────
_SCHEMA_DDL = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id              TEXT PRIMARY KEY,
        username        TEXT UNIQUE NOT NULL,
        email           TEXT UNIQUE,
        password_hash   TEXT NOT NULL,
        role            TEXT DEFAULT 'user',
        plan            TEXT DEFAULT 'trial',
        status          TEXT DEFAULT 'active',
        created_at      TEXT NOT NULL,
        updated_at      TEXT,
        plan_expires_at TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_username ON users(username)",
    "CREATE INDEX IF NOT EXISTS idx_email ON users(email)",
    """
    CREATE TABLE IF NOT EXISTS scan_usage (
        user_id TEXT NOT NULL,
        day     TEXT NOT NULL,
        count   INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, day)
    )
    """,
]

_schema_ready = False
_seeded = False


def _ensure_schema():
    global _schema_ready
    if _schema_ready:
        return
    with _engine.begin() as conn:
        for ddl in _SCHEMA_DDL:
            conn.execute(text(ddl))
    _schema_ready = True


def _seed_admin():
    """Create the ADMIN superadmin user from .env ADMIN_PASSWORD. Uses the
    engine directly (not get_db) to avoid recursion through init_db."""
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    if not admin_password:
        return
    with _engine.begin() as conn:
        c = _Conn(conn)
        if c.execute("SELECT 1 FROM users WHERE username=?", ("ADMIN",)).fetchone():
            return
        now = datetime.datetime.utcnow().isoformat() + "Z"
        c.execute(
            "INSERT INTO users (id, username, email, password_hash, role, plan, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), "ADMIN", "admin@vulnuslab.com",
             _pwd_ctx.hash(admin_password), "superadmin", "superadmin", "active", now),
        )


def init_db():
    """Ensure schema exists and seed the ADMIN user (both idempotent)."""
    global _seeded
    _ensure_schema()
    if not _seeded:
        _seed_admin()
        _seeded = True


@contextmanager
def get_db():
    """Transactional connection (commits on success, rolls back on error).
    Schema/seed are ensured on first use."""
    init_db()
    with _engine.begin() as conn:
        yield _Conn(conn)


# ── Query helpers ───────────────────────────────────────────────────
def get_user_by_id(user_id: str):
    """Return the user row as a dict, or None. Used by verify_token to
    re-validate the live account state on each request (audit #4)."""
    if not user_id:
        return None
    with get_db() as con:
        return con.execute(
            "SELECT id, username, email, role, plan, status, plan_expires_at "
            "FROM users WHERE id=?",
            (user_id,),
        ).fetchone()


def get_scan_usage(user_id: str) -> int:
    """Today's scan count for a user, without incrementing (audit #27/46)."""
    if not user_id:
        return 0
    day = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    with get_db() as con:
        row = con.execute(
            "SELECT count FROM scan_usage WHERE user_id=? AND day=?",
            (user_id, day),
        ).fetchone()
    return int(row["count"]) if row else 0


def bump_scan_usage(user_id: str) -> int:
    """Atomically increment today's scan count for a user and return the new
    total. UTC day buckets. Used by the quota gate (audit #2)."""
    day = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    with get_db() as con:
        row = con.execute(
            "INSERT INTO scan_usage (user_id, day, count) VALUES (?, ?, 1) "
            "ON CONFLICT (user_id, day) DO UPDATE SET count = scan_usage.count + 1 "
            "RETURNING count",
            (user_id, day),
        ).fetchone()
    return int(row["count"]) if row else 1


def hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _pwd_ctx.verify(plain, hashed)
    except Exception:
        return False
