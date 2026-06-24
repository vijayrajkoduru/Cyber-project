"""Org / RBAC / audit data layer (Phase 2.1).

Underscore-prefixed so main.py's tool autoloader skips it; other auth code
imports from here. Sits on top of tools.auth._db (same SQLite DB / get_db).

Role model (per-org, customer-facing):  viewer < member < admin < owner
  - viewer : read results/reports only
  - member : + run scans
  - admin  : + invite/remove users, change roles, org settings
  - owner  : + billing, delete org

This is the DATA layer only — gating/JWT wiring happens in Step 2.
"""
import uuid
import datetime

from tools.auth._db import get_db

_ROLE_RANK = {"viewer": 1, "member": 2, "admin": 3, "owner": 4}
VALID_ROLES = set(_ROLE_RANK)


def _now() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def role_meets(role: str, minimum: str) -> bool:
    """True iff `role` is at least `minimum` in the hierarchy."""
    return _ROLE_RANK.get(role or "", 0) >= _ROLE_RANK.get(minimum, 99)


def get_or_create_personal_org(user_id: str, username: str = "", plan: str = "trial") -> str:
    """Return the user's existing org id, or create a personal org (user=Owner)
    if they have none. Idempotent — safe to call on every login."""
    with get_db() as con:
        row = con.execute(
            "SELECT org_id FROM org_members WHERE user_id=? ORDER BY added_at LIMIT 1",
            (user_id,)).fetchone()
        if row:
            return row["org_id"]
        oid = str(uuid.uuid4())
        now = _now()
        con.execute(
            "INSERT INTO orgs (id, name, plan, owner_user_id, created_at) VALUES (?,?,?,?,?)",
            (oid, username or user_id, plan or "trial", user_id, now))
        con.execute(
            "INSERT INTO org_members (org_id, user_id, role, added_at) VALUES (?,?,?,?)",
            (oid, user_id, "owner", now))
        return oid


def get_user_org_role(user_id: str, org_id: str = None):
    """Return (org_id, role) for the user. If org_id given, that org's role (or
    (None,None) if not a member). Otherwise the user's default/first org."""
    with get_db() as con:
        if org_id:
            r = con.execute(
                "SELECT role FROM org_members WHERE user_id=? AND org_id=?",
                (user_id, org_id)).fetchone()
            return (org_id, r["role"]) if r else (None, None)
        r = con.execute(
            "SELECT org_id, role FROM org_members WHERE user_id=? ORDER BY added_at LIMIT 1",
            (user_id,)).fetchone()
        return (r["org_id"], r["role"]) if r else (None, None)


def get_org(org_id: str):
    with get_db() as con:
        r = con.execute("SELECT * FROM orgs WHERE id=?", (org_id,)).fetchone()
        return dict(r) if r else None


def list_members(org_id: str):
    with get_db() as con:
        return [dict(r) for r in con.execute(
            "SELECT m.user_id, m.role, m.added_at, m.invited_by, u.username, u.email "
            "FROM org_members m JOIN users u ON u.id = m.user_id "
            "WHERE m.org_id=? ORDER BY m.added_at", (org_id,)).fetchall()]


def add_member(org_id: str, user_id: str, role: str = "member", invited_by: str = None):
    if role not in VALID_ROLES:
        role = "member"
    with get_db() as con:
        con.execute(
            "INSERT OR REPLACE INTO org_members (org_id, user_id, role, added_at, invited_by) "
            "VALUES (?,?,?,?,?)", (org_id, user_id, role, _now(), invited_by))


def change_role(org_id: str, user_id: str, role: str) -> bool:
    if role not in VALID_ROLES:
        return False
    with get_db() as con:
        # Never allow removing the last owner (lockout guard).
        if role != "owner":
            owners = con.execute(
                "SELECT COUNT(*) c FROM org_members WHERE org_id=? AND role='owner'",
                (org_id,)).fetchone()["c"]
            cur = con.execute(
                "SELECT role FROM org_members WHERE org_id=? AND user_id=?",
                (org_id, user_id)).fetchone()
            if cur and cur["role"] == "owner" and owners <= 1:
                return False
        con.execute("UPDATE org_members SET role=? WHERE org_id=? AND user_id=?",
                    (role, org_id, user_id))
        return True


def remove_member(org_id: str, user_id: str) -> bool:
    with get_db() as con:
        cur = con.execute("SELECT role FROM org_members WHERE org_id=? AND user_id=?",
                          (org_id, user_id)).fetchone()
        if cur and cur["role"] == "owner":
            owners = con.execute(
                "SELECT COUNT(*) c FROM org_members WHERE org_id=? AND role='owner'",
                (org_id,)).fetchone()["c"]
            if owners <= 1:
                return False  # don't strand an org with no owner
        con.execute("DELETE FROM org_members WHERE org_id=? AND user_id=?",
                    (org_id, user_id))
        return True


def write_audit(action: str, actor_id: str = None, actor_name: str = None,
                org_id: str = None, target: str = None, detail: str = None,
                ip: str = None):
    """Append a security event. Best-effort — never raises (auditing must not
    break the action it records)."""
    try:
        with get_db() as con:
            con.execute(
                "INSERT INTO audit_log (ts, org_id, actor_id, actor_name, action, "
                "target, detail, ip) VALUES (?,?,?,?,?,?,?,?)",
                (_now(), org_id, actor_id, actor_name, action,
                 (target or "")[:300], (detail or "")[:600], ip))
    except Exception:
        pass


def get_audit(org_id: str, limit: int = 500):
    with get_db() as con:
        return [dict(r) for r in con.execute(
            "SELECT ts, actor_name, action, target, detail, ip FROM audit_log "
            "WHERE org_id=? ORDER BY id DESC LIMIT ?", (org_id, int(limit))).fetchall()]


def purge_old_audit(days: int = 365):
    """Retention: drop audit rows older than `days` (default 1 year)."""
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).isoformat() + "Z"
    try:
        with get_db() as con:
            con.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
    except Exception:
        pass
