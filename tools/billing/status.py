"""Trial + billing status endpoints (audit #27/46).

The dashboard polls /api/trial/status and /api/billing/status on load; both
were missing (404, swallowed by empty catches), so the trial banner / scans-
remaining UI never populated. These surface the quota + expiry state that
verify_scan_quota now enforces.
"""
import datetime

from fastapi import APIRouter, Depends

from tools._shared import verify_token, _PLAN_DAILY_LIMITS, _plan_expired
from tools.auth._db import get_scan_usage

router = APIRouter()


def _days_remaining(plan_expires_at) -> int:
    if not plan_expires_at:
        return 0
    try:
        exp = datetime.datetime.fromisoformat(str(plan_expires_at).replace("Z", ""))
        return max(0, (exp - datetime.datetime.utcnow()).days)
    except Exception:
        return 0


@router.get("/api/trial/status")
async def trial_status(payload=Depends(verify_token)):
    plan = (payload.get("plan") or "trial").lower()
    used = get_scan_usage(payload.get("sub"))
    limit = _PLAN_DAILY_LIMITS.get(plan, _PLAN_DAILY_LIMITS["trial"])
    remaining = None if limit is None else max(0, limit - used)
    return {
        "plan": plan,
        "scans_used": used,
        "scans_limit": limit,                 # None = unlimited
        "scans_remaining": remaining,         # None = unlimited
        "days_remaining": _days_remaining(payload.get("plan_expires_at")),
    }


@router.get("/api/billing/status")
async def billing_status(payload=Depends(verify_token)):
    plan = (payload.get("plan") or "trial").lower()
    expires_at = payload.get("plan_expires_at")
    expired = _plan_expired(expires_at)
    days_remaining = _days_remaining(expires_at)

    if expired:
        access = "expired"
    elif plan in ("pro", "team", "enterprise", "unlimited", "superadmin"):
        access = "active"
    else:
        access = "trial"

    return {
        "plan": plan,
        "access": access,                     # trial | active | expired
        "expires_at": expires_at,
        "trial_days_remaining": days_remaining,
        "grace_days_remaining": 0,
    }


def register(app):
    app.include_router(router)
