"""Per-plan scan quota — the billing meter.

One scan == one /api/scan/consent_log call. The dashboard fires consent_log
exactly once at the top of every scan (webapp / recon / every auto-module), and
internal orchestrator fan-out never hits it, so a scan that fans out to N
scanners still costs exactly 1 unit. Enforcement lives in
tools/consent/consent_log.py, which calls check_and_consume() before allowing
the scan to proceed.

Counting is per calendar month ('YYYY-MM'), stored on the user row
(scans_used + usage_period) so it survives restarts. An expired trial/paid
subscription silently falls back to the 'free' tier.

This file is underscore-prefixed so main.py's tool autoloader skips it (it has
no router — it's a helper imported by the consent + admin endpoints).
"""
from __future__ import annotations

import datetime

from tools.auth._db import get_db

# Monthly scan caps per plan. None == unlimited.
# 'free' is the fallback tier an expired trial/paid subscription drops to.
PLAN_CAPS = {
    "free":       10,
    "trial":      25,      # bounded trial; also time-boxed (expires ~7d after signup)
    "modular":    500,     # à la carte: access is gated per-module; scans capped like pro
    "pro":        500,
    "team":       5000,
    "enterprise": None,
    "admin":      None,
    "superadmin": None,
}

# Monthly list price per plan (USD), used only for the Ops Console MRR estimate.
# enterprise is custom-quoted -> 0 here (cannot be auto-estimated). Keep aligned
# with docs/PRICING.md.
PLAN_PRICE = {
    "free":       0,
    "trial":      0,
    "modular":    0,       # per-module pricing lives in tools/_payments/module_catalog.py
    "pro":        49,
    "team":       249,
    "enterprise": 0,
    "admin":      0,
    "superadmin": 0,
}

_UNLIMITED_PLANS = ("admin", "superadmin", "enterprise")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _period(now=None):
    return (now or _now()).strftime("%Y-%m")


def _parse_ts(s):
    if not s:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        return None


def _effective_plan(plan, sub_exp, now):
    """The plan actually in force: an expired subscription falls back to free."""
    plan = (plan or "free").lower()
    if plan in _UNLIMITED_PLANS:
        return plan
    exp = _parse_ts(sub_exp)
    if exp is not None and exp < now:
        return "free"
    return plan if plan in PLAN_CAPS else "free"


def _load(con, identity):
    return con.execute(
        "SELECT username, plan, subscription_expires_at, scans_used, usage_period "
        "FROM users WHERE email=? OR username=? LIMIT 1",
        (identity, identity),
    ).fetchone()


def quota_status(identity):
    """Read-only snapshot for the current period. Never mutates."""
    now = _now()
    period = _period(now)
    with get_db() as con:
        row = _load(con, identity)
    if not row:
        return {"plan": "free", "effective_plan": "free", "cap": PLAN_CAPS["free"],
                "used": 0, "remaining": PLAN_CAPS["free"], "period": period}
    plan = row["plan"] or "free"
    eff = _effective_plan(plan, row["subscription_expires_at"], now)
    cap = PLAN_CAPS.get(eff)
    used = (row["scans_used"] or 0) if (row["usage_period"] or "") == period else 0
    return {"plan": plan, "effective_plan": eff, "cap": cap, "used": used,
            "remaining": (None if cap is None else max(0, cap - used)), "period": period}


def check_and_consume(identity):
    """Atomically check the cap for THIS billing period and, if under it, record
    one scan. Returns dict(ok, plan, effective_plan, cap, used, remaining,
    [message]). ok=False means the cap is reached — the caller MUST block the
    scan. Fails open (ok=True) on any unexpected error so a quota bug can never
    take scanning down."""
    try:
        now = _now()
        period = _period(now)
        with get_db() as con:
            row = _load(con, identity)
            if not row:
                return {"ok": True, "plan": "free", "effective_plan": "free",
                        "cap": PLAN_CAPS["free"], "used": 0, "remaining": PLAN_CAPS["free"]}
            plan = row["plan"] or "free"
            eff = _effective_plan(plan, row["subscription_expires_at"], now)
            cap = PLAN_CAPS.get(eff)
            used = (row["scans_used"] or 0) if (row["usage_period"] or "") == period else 0
            if cap is not None and used >= cap:
                return {"ok": False, "plan": plan, "effective_plan": eff, "cap": cap,
                        "used": used, "remaining": 0,
                        "message": (f"Monthly scan limit reached ({used}/{cap}) on the "
                                    f"{eff} plan. Upgrade your plan to run more scans.")}
            used += 1
            con.execute(
                "UPDATE users SET scans_used=?, usage_period=? WHERE username=?",
                (used, period, row["username"]),
            )
            return {"ok": True, "plan": plan, "effective_plan": eff, "cap": cap,
                    "used": used, "remaining": (None if cap is None else cap - used)}
    except Exception:
        return {"ok": True}   # never hard-fail a scan on a quota error
