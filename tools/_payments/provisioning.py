"""Turn a captured Razorpay payment into an active account.

Idempotent: a `payments` row keyed by razorpay_payment_id guards against
duplicate webhook deliveries (Razorpay retries until it gets a 2xx). On first
delivery we create OR upgrade the user, set plan + subscription_expires_at, and
return everything the caller needs to send the welcome + receipt email.
"""
from __future__ import annotations

import datetime
import secrets
import string
import uuid

from tools.auth._db import get_db, hash_password

try:
    from tools._core.userzone import init_zone as _init_zone
except Exception:
    _init_zone = None


def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def _ensure_payments_table(con):
    con.execute(
        """CREATE TABLE IF NOT EXISTS payments (
               payment_id TEXT PRIMARY KEY,
               order_id   TEXT,
               email      TEXT,
               plan       TEXT,
               amount     INTEGER,
               currency   TEXT,
               status     TEXT,
               created_at TEXT
           )"""
    )


def _gen_password(n: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _gen_username(con, email: str) -> str:
    base = (email.split("@")[0] if email else "user")
    base = "".join(c for c in base if c.isalnum() or c in "_.-")[:24] or "user"
    for _ in range(6):
        candidate = base + secrets.token_hex(2)
        if not con.execute("SELECT 1 FROM users WHERE LOWER(username)=LOWER(?)",
                           (candidate,)).fetchone():
            return candidate
    return base + uuid.uuid4().hex[:8]


def provision_paid_user(*, email, name, plan_key, plan_label, period_days,
                        payment_id, order_id, amount, currency):
    """Create or upgrade the paying user. Returns:
       {already_processed, created, username, email, temp_password|None,
        plan, plan_label, amount}
    """
    email = (email or "").strip().lower()
    now = datetime.datetime.utcnow()
    expires = (now + datetime.timedelta(days=int(period_days))).isoformat() + "Z"
    created = False
    temp_password = None
    new_user_id = None

    with get_db() as con:
        _ensure_payments_table(con)

        if payment_id and con.execute(
                "SELECT 1 FROM payments WHERE payment_id=?", (payment_id,)).fetchone():
            return {"already_processed": True, "created": False, "email": email,
                    "username": None, "temp_password": None,
                    "plan": plan_key, "plan_label": plan_label, "amount": amount}

        row = con.execute("SELECT id, username FROM users WHERE LOWER(email)=?",
                          (email,)).fetchone()
        if row:
            username = row["username"]
            con.execute(
                "UPDATE users SET plan=?, subscription_expires_at=?, status='active', updated_at=? WHERE id=?",
                (plan_key, expires, _now_iso(), row["id"]),
            )
        else:
            created = True
            new_user_id = str(uuid.uuid4())
            username = _gen_username(con, email)
            temp_password = _gen_password()
            con.execute(
                "INSERT INTO users (id, username, email, password_hash, role, plan, status, created_at, subscription_expires_at) "
                "VALUES (?, ?, ?, ?, 'user', ?, 'active', ?, ?)",
                (new_user_id, username, email, hash_password(temp_password),
                 plan_key, _now_iso(), expires),
            )

        con.execute(
            "INSERT OR REPLACE INTO payments (payment_id, order_id, email, plan, amount, currency, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'captured', ?)",
            (payment_id, order_id, email, plan_key, amount, currency, _now_iso()),
        )

    # Walled-off data zone for brand-new users (best-effort, never blocks).
    if created and new_user_id and _init_zone is not None:
        try:
            _init_zone(new_user_id)
        except Exception:
            pass

    return {"already_processed": False, "created": created, "username": username,
            "email": email, "temp_password": temp_password, "plan": plan_key,
            "plan_label": plan_label, "amount": amount}
