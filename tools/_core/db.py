"""Database connection factory — the foundation for the SQLite -> Postgres
migration.

The codebase currently opens sqlite3 connections directly in ~13 places. This
module gives them ONE place to get a connection and ONE paramstyle helper, so
the cutover to Postgres is incremental and reversible:

    Today  (default):  DATABASE_URL unset  -> sqlite3, identical behaviour.
    Cutover:           DATABASE_URL=postgresql://user:pw@host/db -> psycopg.

psycopg is imported lazily and ONLY when a postgres URL is configured, so the
SQLite path adds no new dependency and the current production boot is byte-for-
byte unchanged.

Migrating a call site:
    # before
    con = sqlite3.connect(DB_PATH)
    con.execute("SELECT * FROM users WHERE id = ?", (uid,))
    # after
    from tools._core.db import get_conn, q
    con = get_conn(DB_PATH)                      # path ignored when DATABASE_URL set
    con.execute(q("SELECT * FROM users WHERE id = ?"), (uid,))

See docs/POSTGRES-MIGRATION.md for the full plan + data-copy script.
"""
from __future__ import annotations

import os
import sqlite3

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
IS_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://"))


def q(sql: str) -> str:
    """Translate sqlite '?' placeholders to the active backend's paramstyle.
    No-op for sqlite. For postgres, '?' -> '%s' (psycopg paramstyle='format').
    Naive but correct for the codebase's parameter usage (no literal '?' in
    SQL text); call sites that embed a literal '?' must not use q()."""
    if IS_POSTGRES:
        return sql.replace("?", "%s")
    return sql


def get_conn(sqlite_path: str | None = None, *, timeout: float = 10.0):
    """Return a DB-API connection for the active backend.

    sqlite_path is used only for the SQLite backend; it is ignored when
    DATABASE_URL points at Postgres (the URL fully specifies the target)."""
    if IS_POSTGRES:
        try:
            import psycopg  # psycopg3, optional — only needed for Postgres
        except ModuleNotFoundError as exc:  # pragma: no cover - env dependent
            raise RuntimeError(
                "DATABASE_URL is set to Postgres but 'psycopg' is not installed. "
                "Add psycopg[binary] to requirements and rebuild."
            ) from exc
        return psycopg.connect(DATABASE_URL, connect_timeout=int(timeout))
    if sqlite_path is None:
        raise ValueError("sqlite_path is required for the SQLite backend")
    con = sqlite3.connect(sqlite_path, timeout=timeout)
    con.execute("PRAGMA journal_mode=WAL")       # better concurrent-read posture
    con.execute("PRAGMA foreign_keys=ON")
    return con


def backend_name() -> str:
    return "postgres" if IS_POSTGRES else "sqlite"
