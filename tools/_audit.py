"""Lightweight append-only audit log for sensitive actions.

Records security-relevant events (password/email changes, account deletion,
admin plan changes, credential access) to an append-only SQLite log at
/app/data/audit_log.db so they survive restarts and can be reviewed in the Ops
Console. Underscore-prefixed so the tool autoloader skips it (helper, no router).
"""
from __future__ import annotations

import datetime
import os
import sqlite3
import threading

_DB = os.environ.get("AUDIT_DB_PATH", "/app/data/audit_log.db")
_LOCK = threading.Lock()
_INIT = False


def _init():
    global _INIT
    if _INIT:
        return
    os.makedirs(os.path.dirname(_DB), exist_ok=True)
    with sqlite3.connect(_DB) as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT NOT NULL,
                action    TEXT NOT NULL,
                actor     TEXT,
                target    TEXT,
                detail    TEXT,
                client_ip TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
    _INIT = True


def audit_log(action, actor="", target="", detail="", request=None):
    """Record one event. Never raises — auditing must not break the action."""
    try:
        _init()
        ip = ""
        if request is not None:
            ip = (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                  or (request.client.host if request.client else ""))
        with _LOCK, sqlite3.connect(_DB) as c:
            c.execute(
                "INSERT INTO audit_log (ts, action, actor, target, detail, client_ip) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 action, actor, target, (detail or "")[:300], ip),
            )
    except Exception:
        pass


def recent(limit=200):
    """Read the most recent events (for the Ops Console)."""
    try:
        _init()
        with sqlite3.connect(_DB) as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute(
                "SELECT ts, action, actor, target, detail, client_ip "
                "FROM audit_log ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()]
    except Exception:
        return []
