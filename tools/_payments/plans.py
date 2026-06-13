"""Checkout plan catalogue for Razorpay.

Maps a public checkout `plan_id` -> Razorpay amount (USD cents) + the internal
quota plan key (one of tools/_quota.PLAN_CAPS: pro / team / enterprise) that the
account is switched to on successful payment, plus the access period in days.

PRICES BELOW ARE PLACEHOLDERS - confirm the final USD amounts before going live.
(Charging USD via Razorpay requires International Payments enabled on the account.)
"""
from __future__ import annotations

# amount is in cents (USD * 100). `plan` must be a tools/_quota.PLAN_CAPS key.
PAYMENT_PLANS = {
    "pro_monthly":  {"label": "Pro — Monthly",  "plan": "pro",  "amount": 4900,   "currency": "USD", "period_days": 30},
    "pro_annual":   {"label": "Pro — Annual",   "plan": "pro",  "amount": 49000,  "currency": "USD", "period_days": 365},
    "team_monthly": {"label": "Team — Monthly", "plan": "team", "amount": 24900,  "currency": "USD", "period_days": 30},
    "team_annual":  {"label": "Team — Annual",  "plan": "team", "amount": 249000, "currency": "USD", "period_days": 365},
}
# TODO(pricing): replace the amounts above with your confirmed USD prices.


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
