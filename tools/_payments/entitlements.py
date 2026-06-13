"""Module entitlement checks — which modules an account may access.

A paying customer owns a set of module ids (users.modules CSV) under a single
subscription_expires_at. Rules:
  - admin / superadmin                 -> all modules ('*')
  - enterprise plan                    -> all modules ('*')
  - active free trial (plan='trial')   -> all modules ('*') during the trial window
  - otherwise (e.g. plan='modular')    -> exactly the modules in the CSV, while not expired
  - expired                            -> no module access (re-subscribe to unlock)

Read-only; never mutates. Granting happens in provisioning on a captured payment.
"""
from __future__ import annotations

import datetime

from tools.auth._db import get_db

_ALL_ACCESS_ROLES = ("admin", "superadmin")
_ALL_ACCESS_PLANS = ("enterprise", "trial")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _parse_ts(s):
    if not s:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        return None


def parse_modules(csv):
    return [m.strip() for m in (csv or "").split(",") if m.strip()]


def _load(con, identity):
    # identity may be the JWT 'sub' (user id / UUID), an email, or a username.
    return con.execute(
        "SELECT role, plan, subscription_expires_at, modules "
        "FROM users WHERE id=? OR email=? OR username=? LIMIT 1",
        (identity, identity, identity),
    ).fetchone()


def owned_modules(identity):
    """Module ids the identity can access right now. ['*'] means all modules."""
    if not identity:
        return []
    try:
        with get_db() as con:
            row = _load(con, identity)
    except Exception:
        return []
    if not row:
        return []
    if (row["role"] or "").lower() in _ALL_ACCESS_ROLES:
        return ["*"]
    exp = _parse_ts(row["subscription_expires_at"])
    not_expired = (exp is None) or (exp >= _now())
    if not_expired and (row["plan"] or "").lower() in _ALL_ACCESS_PLANS:
        return ["*"]
    if not_expired:
        return parse_modules(row["modules"])
    return []


def has_module(identity, module_id) -> bool:
    mods = owned_modules(identity)
    return ("*" in mods) or (module_id in mods)
