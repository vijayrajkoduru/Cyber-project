#!/usr/bin/env python3
"""Wipe ALL users and create a single fresh superadmin.

DESTRUCTIVE: deletes every row in the `users` table. Run on the host
where the backend lives, against the real users.db.

Usage (inside the backend container is easiest — passlib is installed there):

    docker exec -it oscp_backend python /app/scripts/reset_superuser.py

Credentials:
  - Username:  $NEW_ADMIN_USER     (default: ADMIN)
  - Password:  $NEW_ADMIN_PASSWORD (if unset, a strong one is generated + printed)
  - Email:     $NEW_ADMIN_EMAIL    (default: admin@vulnuslab.com)

DB path follows the app: $USERS_DB (default: /app/data/users.db)
"""
import os
import sys
import uuid
import secrets
import string
import sqlite3
import datetime
from pathlib import Path

try:
    from passlib.context import CryptContext
except ImportError:
    sys.exit("passlib not installed here. Run this INSIDE the backend container "
             "(docker exec -it oscp_backend python /app/scripts/reset_superuser.py).")

DB_PATH = Path(os.getenv("USERS_DB", "/app/data/users.db"))
USERNAME = os.getenv("NEW_ADMIN_USER", "ADMIN")
EMAIL = os.getenv("NEW_ADMIN_EMAIL", "admin@vulnuslab.com")
PASSWORD = os.getenv("NEW_ADMIN_PASSWORD", "")

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _generate_password(n: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    return "".join(secrets.choice(alphabet) for _ in range(n))


def main() -> None:
    if not DB_PATH.exists():
        sys.exit(f"users.db not found at {DB_PATH}. Set USERS_DB or run on the host.")

    password = PASSWORD or _generate_password()

    con = sqlite3.connect(DB_PATH)
    try:
        # Make sure the table exists (matches tools/auth/_db.py schema).
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
        """)
        deleted = con.execute("DELETE FROM users").rowcount
        now = datetime.datetime.utcnow().isoformat() + "Z"
        con.execute(
            "INSERT INTO users (id, username, email, password_hash, role, plan, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), USERNAME, EMAIL, _pwd_ctx.hash(password),
             "superadmin", "superadmin", "active", now),
        )
        con.commit()
    finally:
        con.close()

    print("=" * 56)
    print(f"  Deleted {deleted} existing user(s).")
    print("  New superadmin created:")
    print(f"    username : {USERNAME}")
    print(f"    email    : {EMAIL}")
    print(f"    password : {password}")
    print("  Save this password now — it is bcrypt-hashed in the DB")
    print("  and cannot be recovered.")
    print("=" * 56)


if __name__ == "__main__":
    main()
