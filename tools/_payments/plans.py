"""Checkout plan catalogue for Razorpay.

Maps a public checkout `plan_id` -> Razorpay amount (INR paise) + the internal
quota plan key (one of tools/_quota.PLAN_CAPS: pro / team / enterprise) that the
account is switched to on successful payment, plus the access period in days.

PRICES ARE FINAL / CONFIRMED (2026-06-14, owner-approved). Do NOT change without
owner sign-off — these are the live amounts charged in production via Razorpay.
USD list prices live in tools/_quota.PLAN_PRICE (pro $49 / team $249).
"""
from __future__ import annotations

# amount is in PAISE (INR * 100). `plan` must be a tools/_quota.PLAN_CAPS key.
PAYMENT_PLANS = {
    "pro_monthly":  {"label": "Pro — Monthly",  "plan": "pro",  "amount": 399900,   "currency": "INR", "period_days": 30},
    "pro_annual":   {"label": "Pro — Annual",   "plan": "pro",  "amount": 3999000,  "currency": "INR", "period_days": 365},
    "team_monthly": {"label": "Team — Monthly", "plan": "team", "amount": 1999900,  "currency": "INR", "period_days": 30},
    "team_annual":  {"label": "Team — Annual",  "plan": "team", "amount": 19999000, "currency": "INR", "period_days": 365},
}
# Prices CONFIRMED FINAL 2026-06-14 (owner-approved). Module one-time prices live
# in the module catalogue; both surfaced via /api/payment/config.


def get_plan(plan_id):
    """Return the plan spec for a checkout plan_id, or None."""
    return PAYMENT_PLANS.get((plan_id or "").strip())


def public_plans():
    """Plan list safe to expose to the checkout page."""
    return [
        {"id": pid, "label": p["label"], "amount": p["amount"],
         "currency": p["currency"], "period_days": p["period_days"]}
        for pid, p in PAYMENT_PLANS.items()
    ]
