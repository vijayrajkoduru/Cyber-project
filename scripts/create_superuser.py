#!/usr/bin/env python3
"""Create (or update) a VulnusLab superuser in the users database.

Uses the backend's own DB helpers (tools.auth._db) so the row is hashed and
shaped exactly like the seeded ADMIN account (role=superadmin, plan=superadmin,
status=active, bcrypt password).

RUN IT INSIDE THE BACKEND CONTAINER so it writes the real production DB
(/app/data/users.db), not a stray local file:

  docker compose exec backend python scripts/create_superuser.py \
      --username alice --email alice@vulnuslab.com

Omit --password to be prompted securely (keeps it out of shell history).
Use --force to reset an existing user's password/role.
"""
from __future__ import annotations
import argparse
import datetime
import getpass
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.auth._db import get_db, hash_password  # noqa: E402
try:
    from tools.auth._db import DB_PATH  # type: ignore
except Exception:
    DB_PATH = "(resolved by tools.auth._db)"


def main():
    ap = argparse.ArgumentParser(description="Create/update a VulnusLab superuser")
    ap.add_argument("--username", required=True)
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", help="if omitted, you are prompted (no shell history)")
    ap.add_argument("--role", default="superadmin", help="default: superadmin")
    ap.add_argument("--plan", default="superadmin", help="default: superadmin")
    ap.add_argument("--force", action="store_true",
                    help="update password/role if the user already exists")
    args = ap.parse_args()

    pw = args.password or getpass.getpass("New superuser password: ")
    if len(pw) < 8:
        print("ERROR: password must be at least 8 characters.")
        sys.exit(2)

    now = datetime.datetime.utcnow().isoformat() + "Z"
    hashed = hash_password(pw)

    with get_db() as con:
        row = con.execute(
            "SELECT id FROM users WHERE LOWER(username)=LOWER(?) OR LOWER(email)=LOWER(?)",
            (args.username, args.email),
        ).fetchone()
        if row and not args.force:
            print(f"ERROR: a user matching username '{args.username}' or email "
                  f"'{args.email}' already exists. Re-run with --force to update it.")
            sys.exit(1)
        if row:
            uid = row["id"]
            con.execute(
                "UPDATE users SET username=?, email=?, password_hash=?, role=?, plan=?, "
                "status='active', updated_at=? WHERE id=?",
                (args.username, args.email, hashed, args.role, args.plan, now, uid),
            )
            action = "UPDATED"
        else:
            uid = str(uuid.uuid4())
            con.execute(
                "INSERT INTO users (id, username, email, password_hash, role, plan, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (uid, args.username, args.email, hashed, args.role, args.plan, "active", now),
            )
            action = "CREATED"

    print(f"{action} superuser")
    print(f"  username : {args.username}")
    print(f"  email    : {args.email}")
    print(f"  role     : {args.role}")
    print(f"  plan     : {args.plan}")
    print(f"  id       : {uid}")
    print(f"  db       : {DB_PATH}")
    print("Log in at the dashboard with this username + the password you set.")


if __name__ == "__main__":
    main()
