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
    # ── Enterprise: tamper-evident audit log (who did what, when) ─────
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id         TEXT PRIMARY KEY,
        ts         TEXT NOT NULL,
        actor_id   TEXT,
        actor_name TEXT,
        action     TEXT NOT NULL,
        target     TEXT,
        ip         TEXT,
        detail     TEXT,
        status     TEXT DEFAULT 'ok'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)",
    "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)",
    # ── Enterprise: programmatic API keys (hashed at rest) ────────────
    """
    CREATE TABLE IF NOT EXISTS api_keys (
        id          TEXT PRIMARY KEY,
        user_id     TEXT NOT NULL,
        name        TEXT,
        prefix      TEXT NOT NULL,
        key_hash    TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        last_used_at TEXT,
        revoked     INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_apikey_user ON api_keys(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_apikey_prefix ON api_keys(prefix)",
    # ── Enterprise Phase 2: email verification + MFA (idempotent ALTERs) ─
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled INTEGER DEFAULT 0",
    """
    CREATE TABLE IF NOT EXISTS email_tokens (
        token      TEXT PRIMARY KEY,
        user_id    TEXT NOT NULL,
        purpose    TEXT NOT NULL DEFAULT 'verify',
        expires_at TEXT NOT NULL,
        used       INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_emailtok_user ON email_tokens(user_id)",
    # ── Enterprise Phase 3: organizations + RBAC membership ───────────
    """
    CREATE TABLE IF NOT EXISTS organizations (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        owner_id   TEXT NOT NULL,
        plan       TEXT DEFAULT 'team',
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS org_members (
        org_id    TEXT NOT NULL,
        user_id   TEXT NOT NULL,
        role      TEXT NOT NULL DEFAULT 'member',
        added_at  TEXT NOT NULL,
        PRIMARY KEY (org_id, user_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_orgmem_user ON org_members(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_orgmem_org ON org_members(org_id)",
]

# Org role hierarchy — higher number = more privilege.
ORG_ROLES = {"member": 1, "admin": 2, "owner": 3}

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


# ── Enterprise: audit log ───────────────────────────────────────────
def record_audit(action: str, *, actor_id=None, actor_name=None, target=None,
                 ip=None, detail=None, status="ok") -> None:
    """Append an audit event. Never raises — an audit-write failure must not
    break the action being audited (logged instead)."""
    try:
        with get_db() as con:
            con.execute(
                "INSERT INTO audit_log (id, ts, actor_id, actor_name, action, "
                "target, ip, detail, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), datetime.datetime.utcnow().isoformat() + "Z",
                 actor_id, actor_name, action, target, ip,
                 (detail if isinstance(detail, str) else None), status),
            )
    except Exception as exc:  # pragma: no cover - audit must never break flow
        import logging
        logging.getLogger("vulnuslab.audit").warning("audit write failed: %s", exc)


def list_audit(limit: int = 100, offset: int = 0, actor_id=None, action=None):
    """Read audit events newest-first, with optional filters + pagination."""
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    where, params = [], []
    if actor_id:
        where.append("actor_id=?"); params.append(actor_id)
    if action:
        where.append("action=?"); params.append(action)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    with get_db() as con:
        rows = con.execute(
            f"SELECT id, ts, actor_id, actor_name, action, target, ip, detail, status "
            f"FROM audit_log {clause} ORDER BY ts DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        total = con.execute(
            f"SELECT COUNT(*) AS n FROM audit_log {clause}", tuple(params)
        ).fetchone()
    return {"items": rows, "total": int(total["n"]) if total else 0,
            "limit": limit, "offset": offset}


# ── Enterprise: API keys ────────────────────────────────────────────
def create_api_key(user_id: str, name: str = ""):
    """Mint an API key. Returns (full_secret, row). The full secret is shown
    ONCE; only its hash is stored. Format: vlk_<prefix>_<random>."""
    import secrets as _secrets
    prefix = _secrets.token_hex(4)                  # 8-char public id
    secret = _secrets.token_urlsafe(32)             # the part we hash
    full = f"vlk_{prefix}_{secret}"
    kid = str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat() + "Z"
    with get_db() as con:
        con.execute(
            "INSERT INTO api_keys (id, user_id, name, prefix, key_hash, created_at, revoked) "
            "VALUES (?, ?, ?, ?, ?, ?, 0)",
            (kid, user_id, name or "api-key", prefix, _pwd_ctx.hash(full), now),
        )
    return full, {"id": kid, "name": name or "api-key", "prefix": prefix,
                  "created_at": now, "revoked": False}


def list_api_keys(user_id: str):
    """List a user's keys (metadata only — never the secret)."""
    with get_db() as con:
        return con.execute(
            "SELECT id, name, prefix, created_at, last_used_at, revoked "
            "FROM api_keys WHERE user_id=? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()


def revoke_api_key(user_id: str, key_id: str) -> bool:
    with get_db() as con:
        r = con.execute(
            "UPDATE api_keys SET revoked=1 WHERE id=? AND user_id=? AND revoked=0",
            (key_id, user_id),
        )
        return r.rowcount > 0


def resolve_api_key(full_secret: str):
    """Verify an incoming API key. Returns the owning user row (active only)
    or None. Matches by prefix then bcrypt-verifies the full secret."""
    if not full_secret or not full_secret.startswith("vlk_"):
        return None
    parts = full_secret.split("_", 2)
    if len(parts) != 3:
        return None
    prefix = parts[1]
    with get_db() as con:
        candidates = con.execute(
            "SELECT id, user_id, key_hash FROM api_keys WHERE prefix=? AND revoked=0",
            (prefix,),
        ).fetchall()
        match = next((c for c in candidates
                      if verify_password(full_secret, c["key_hash"])), None)
        if not match:
            return None
        con.execute("UPDATE api_keys SET last_used_at=? WHERE id=?",
                    (datetime.datetime.utcnow().isoformat() + "Z", match["id"]))
        return con.execute(
            "SELECT id, username, email, role, plan, status, plan_expires_at "
            "FROM users WHERE id=?",
            (match["user_id"],),
        ).fetchone()


# ── Enterprise: email verification ──────────────────────────────────
def create_email_token(user_id: str, purpose: str = "verify", ttl_hours: int = 48) -> str:
    """Mint a single-use email token (e.g. for verify / password reset)."""
    import secrets as _secrets
    tok = _secrets.token_urlsafe(32)
    exp = (datetime.datetime.utcnow() + datetime.timedelta(hours=ttl_hours)).isoformat() + "Z"
    with get_db() as con:
        con.execute(
            "INSERT INTO email_tokens (token, user_id, purpose, expires_at, used) "
            "VALUES (?, ?, ?, ?, 0)",
            (tok, user_id, purpose, exp),
        )
    return tok


def consume_email_token(token: str, purpose: str = "verify"):
    """Validate + burn a token. Returns user_id on success, else None."""
    if not token:
        return None
    now = datetime.datetime.utcnow().isoformat() + "Z"
    with get_db() as con:
        row = con.execute(
            "SELECT user_id, expires_at, used FROM email_tokens WHERE token=? AND purpose=?",
            (token, purpose),
        ).fetchone()
        if not row or row["used"] or row["expires_at"] < now:
            return None
        con.execute("UPDATE email_tokens SET used=1 WHERE token=?", (token,))
        return row["user_id"]


def mark_email_verified(user_id: str) -> None:
    with get_db() as con:
        con.execute("UPDATE users SET email_verified=1 WHERE id=?", (user_id,))


def is_email_verified(user_id: str) -> bool:
    with get_db() as con:
        row = con.execute("SELECT email_verified FROM users WHERE id=?", (user_id,)).fetchone()
    return bool(row and row["email_verified"])


# ── Enterprise: MFA / TOTP ──────────────────────────────────────────
def set_mfa_secret(user_id: str, secret: str) -> None:
    """Store a pending TOTP secret (mfa not enabled until a code is verified)."""
    with get_db() as con:
        con.execute("UPDATE users SET mfa_secret=? WHERE id=?", (secret, user_id))


def enable_mfa(user_id: str) -> None:
    with get_db() as con:
        con.execute("UPDATE users SET mfa_enabled=1 WHERE id=?", (user_id,))


def disable_mfa(user_id: str) -> None:
    with get_db() as con:
        con.execute("UPDATE users SET mfa_enabled=0, mfa_secret=NULL WHERE id=?", (user_id,))


def get_mfa(user_id: str):
    """Return {'enabled': bool, 'secret': str|None} for a user."""
    with get_db() as con:
        row = con.execute(
            "SELECT mfa_enabled, mfa_secret FROM users WHERE id=?", (user_id,)
        ).fetchone()
    if not row:
        return {"enabled": False, "secret": None}
    return {"enabled": bool(row["mfa_enabled"]), "secret": row["mfa_secret"]}


# ── Enterprise: organizations + RBAC ────────────────────────────────
def create_org(name: str, owner_id: str, plan: str = "team"):
    """Create an org and make the creator its owner (atomic)."""
    oid = str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat() + "Z"
    with get_db() as con:
        con.execute(
            "INSERT INTO organizations (id, name, owner_id, plan, created_at) "
            "VALUES (?, ?, ?, ?, ?)", (oid, name, owner_id, plan, now))
        con.execute(
            "INSERT INTO org_members (org_id, user_id, role, added_at) "
            "VALUES (?, ?, 'owner', ?)", (oid, owner_id, now))
    return {"id": oid, "name": name, "owner_id": owner_id, "plan": plan, "created_at": now}


def get_org(org_id: str):
    with get_db() as con:
        return con.execute(
            "SELECT id, name, owner_id, plan, created_at FROM organizations WHERE id=?",
            (org_id,)).fetchone()


def list_user_orgs(user_id: str):
    """Orgs the user belongs to, with their role in each."""
    with get_db() as con:
        return con.execute(
            "SELECT o.id, o.name, o.plan, o.created_at, m.role "
            "FROM organizations o JOIN org_members m ON m.org_id=o.id "
            "WHERE m.user_id=? ORDER BY o.created_at", (user_id,)).fetchall()


def get_member_role(org_id: str, user_id: str):
    """Return the user's role string in the org, or None if not a member."""
    with get_db() as con:
        row = con.execute(
            "SELECT role FROM org_members WHERE org_id=? AND user_id=?",
            (org_id, user_id)).fetchone()
    return row["role"] if row else None


def has_org_role(org_id: str, user_id: str, min_role: str) -> bool:
    role = get_member_role(org_id, user_id)
    if not role:
        return False
    return ORG_ROLES.get(role, 0) >= ORG_ROLES.get(min_role, 99)


def list_org_members(org_id: str):
    with get_db() as con:
        return con.execute(
            "SELECT m.user_id, m.role, m.added_at, u.username, u.email "
            "FROM org_members m JOIN users u ON u.id=m.user_id "
            "WHERE m.org_id=? ORDER BY m.added_at", (org_id,)).fetchall()


def add_org_member(org_id: str, user_id: str, role: str = "member") -> bool:
    if role not in ORG_ROLES:
        return False
    now = datetime.datetime.utcnow().isoformat() + "Z"
    with get_db() as con:
        con.execute(
            "INSERT INTO org_members (org_id, user_id, role, added_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT (org_id, user_id) DO UPDATE SET role=EXCLUDED.role",
            (org_id, user_id, role, now))
    return True


def set_member_role(org_id: str, user_id: str, role: str) -> bool:
    if role not in ORG_ROLES:
        return False
    with get_db() as con:
        r = con.execute("UPDATE org_members SET role=? WHERE org_id=? AND user_id=?",
                        (role, org_id, user_id))
        return r.rowcount > 0


def remove_org_member(org_id: str, user_id: str) -> bool:
    """Remove a member. Refuses to remove the org owner (must transfer first)."""
    org = get_org(org_id)
    if org and org["owner_id"] == user_id:
        return False
    with get_db() as con:
        r = con.execute("DELETE FROM org_members WHERE org_id=? AND user_id=?",
                        (org_id, user_id))
        return r.rowcount > 0


def find_user_by_email(email: str):
    with get_db() as con:
        return con.execute(
            "SELECT id, username, email FROM users WHERE LOWER(email)=LOWER(?)",
            (email,)).fetchone()
