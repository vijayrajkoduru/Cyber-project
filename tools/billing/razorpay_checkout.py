"""Razorpay checkout for the Pro plan (RAZORPAY-BILLING-V1).

Flow:
  1. POST /api/billing/checkout        -> creates a Razorpay Payment Link for the
     logged-in user and returns {"url": <hosted checkout>}.
  2. User pays; Razorpay redirects to <app>/?billing=success&razorpay_*=...
  3. Pro is granted by EITHER (both idempotent per payment id):
       - POST /api/billing/razorpay/verify   (frontend, with the callback params:
         signature checked with the key secret, then the link is re-fetched from
         the Razorpay API and must be paid, owned by this user, right amount), or
       - POST /api/billing/payment-webhook (alias: /api/billing/razorpay/webhook)  (Razorpay server-to-server,
         X-Razorpay-Signature = HMAC-SHA256(raw body, RAZORPAY_WEBHOOK_SECRET),
         event payment_link.paid).

Env: RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET,
     RAZORPAY_PRO_AMOUNT (minor units, default 19900 = $199.00),
     RAZORPAY_CURRENCY (default USD - needs International Payments enabled),
     PRO_PERIOD_DAYS (default 30).
"""
import datetime
import hashlib
import hmac
import json
import logging
import os
import uuid
from typing import Optional
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from tools._shared import verify_token
from tools.auth._db import get_db, get_user_by_id, record_audit

log = logging.getLogger("vulnuslab.billing")
router = APIRouter()

_API = "https://api.razorpay.com/v1"
_NO_DOWNGRADE = {"enterprise", "superadmin", "unlimited"}


def _cfg():
    key_id = (os.getenv("RAZORPAY_KEY_ID") or "").strip()
    secret = (os.getenv("RAZORPAY_KEY_SECRET") or "").strip()
    if not key_id or not secret:
        raise HTTPException(503, "Payments are not configured")
    return key_id, secret


def _amount() -> int:
    try:
        return int(os.getenv("RAZORPAY_PRO_AMOUNT", "19900"))
    except ValueError:
        return 19900


def _currency() -> str:
    return (os.getenv("RAZORPAY_CURRENCY") or "USD").strip().upper()


def _period_days() -> int:
    try:
        return max(1, int(os.getenv("PRO_PERIOD_DAYS", "30")))
    except ValueError:
        return 30


def _allowed_origins():
    raw = os.getenv("CORS_ORIGINS", "")
    return [o.strip().rstrip("/") for o in raw.split(",") if o.strip() and o.strip() != "*"]


def _callback_url(requested: Optional[str]) -> str:
    """Only redirect back to one of our own origins (no open redirect)."""
    allowed = _allowed_origins()
    if requested:
        p = urlparse(requested)
        origin = f"{p.scheme}://{p.netloc}".rstrip("/")
        if p.scheme in ("http", "https") and origin in allowed:
            return f"{origin}/?billing=success"
    if allowed:
        https = [o for o in allowed if o.startswith("https://")]
        return f"{(https or allowed)[0]}/?billing=success"
    raise HTTPException(503, "Payments are not configured (no CORS_ORIGINS)")


def _grant_pro(user_id: str, payment_id: str, link_id: str, amount: int,
               currency: str, source: str) -> dict:
    """Idempotently extend the user's Pro plan for one paid payment."""
    now = datetime.datetime.utcnow()
    with get_db() as con:
        if con.execute("SELECT 1 FROM billing_payments WHERE payment_id=?",
                       (payment_id,)).fetchone():
            return {"granted": False, "already_processed": True}
        user = con.execute("SELECT id, username, plan, plan_expires_at FROM users WHERE id=?",
                           (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found")
        con.execute(
            "INSERT INTO billing_payments (payment_id, user_id, link_id, amount, currency, source, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (payment_id, user_id, link_id, int(amount), currency, source, now.isoformat() + "Z"))
        plan = (user["plan"] or "trial").lower()
        if plan in _NO_DOWNGRADE:
            new_exp = user["plan_expires_at"]
        else:
            base = now
            if plan == "pro" and user["plan_expires_at"]:
                try:
                    cur = datetime.datetime.fromisoformat(str(user["plan_expires_at"]).replace("Z", ""))
                    base = max(now, cur)
                except ValueError:
                    pass
            new_exp = (base + datetime.timedelta(days=_period_days())).isoformat() + "Z"
            con.execute("UPDATE users SET plan=?, plan_expires_at=? WHERE id=?",
                        ("pro", new_exp, user_id))
    record_audit("billing.pro_granted", actor_id=user_id, actor_name=user["username"],
                 target=payment_id, status="ok",
                 detail=json.dumps({"link": link_id, "amount": amount, "currency": currency,
                                    "source": source, "expires": new_exp}))
    return {"granted": True, "plan_expires_at": new_exp}


def _link_matches(link: dict, user_id: str) -> bool:
    notes = link.get("notes") or {}
    return (link.get("status") == "paid"
            and notes.get("user_id") == user_id
            and notes.get("plan") == "pro"
            and int(link.get("amount") or 0) >= _amount()
            and (link.get("currency") or "").upper() == _currency())


def _paid_payment_id(link: dict) -> Optional[str]:
    for p in link.get("payments") or []:
        if p.get("status") == "captured" and p.get("payment_id"):
            return p["payment_id"]
    return None


class CheckoutRequest(BaseModel):
    redirect_url: Optional[str] = None


@router.post("/api/account/upgrade")  # ADBLOCK-SAFE-V1 alias
@router.post("/api/billing/checkout")
async def checkout(req: CheckoutRequest, payload=Depends(verify_token)):
    key_id, secret = _cfg()
    user = get_user_by_id(payload.get("sub")) or {}
    body = {
        "amount": _amount(),
        "currency": _currency(),
        "accept_partial": False,
        "description": f"VulnusLab Pro - {_period_days()} days",
        "reference_id": f"vl_{uuid.uuid4().hex[:24]}",
        "notify": {"sms": False, "email": bool(user.get("email"))},
        "reminder_enable": False,
        "callback_url": _callback_url(req.redirect_url),
        "callback_method": "get",
        "notes": {"user_id": payload.get("sub"), "plan": "pro"},
    }
    if user.get("email"):
        body["customer"] = {"email": user["email"], "name": user.get("username") or ""}
    try:
        r = requests.post(f"{_API}/payment_links", auth=(key_id, secret), json=body, timeout=20)
    except requests.RequestException as e:
        log.error("razorpay checkout network error: %s", e)
        raise HTTPException(502, "Payment provider unreachable, try again")
    if r.status_code >= 400:
        try:
            desc = r.json().get("error", {}).get("description", "")
        except ValueError:
            desc = ""
        log.error("razorpay checkout failed %s: %s", r.status_code, desc)
        raise HTTPException(502, f"Payment provider error: {desc or r.status_code}")
    data = r.json()
    record_audit("billing.checkout_started", actor_id=payload.get("sub"),
                 actor_name=payload.get("username"), target=data.get("id"), status="ok")
    return {"url": data.get("short_url"), "link_id": data.get("id")}


class VerifyRequest(BaseModel):
    razorpay_payment_id: str
    razorpay_payment_link_id: str
    razorpay_payment_link_reference_id: str = ""
    razorpay_payment_link_status: str
    razorpay_signature: str


@router.post("/api/account/upgrade/confirm")  # ADBLOCK-SAFE-V1 alias
@router.post("/api/billing/razorpay/verify")
async def verify_callback(req: VerifyRequest, payload=Depends(verify_token)):
    key_id, secret = _cfg()
    msg = "|".join([req.razorpay_payment_link_id, req.razorpay_payment_link_reference_id,
                    req.razorpay_payment_link_status, req.razorpay_payment_id])
    expected = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, req.razorpay_signature or ""):
        raise HTTPException(400, "Invalid payment signature")
    try:
        r = requests.get(f"{_API}/payment_links/{req.razorpay_payment_link_id}",
                         auth=(key_id, secret), timeout=20)
        r.raise_for_status()
        link = r.json()
    except (requests.RequestException, ValueError) as e:
        log.error("razorpay verify fetch failed: %s", e)
        raise HTTPException(502, "Could not confirm payment, it will be applied shortly")
    if not _link_matches(link, payload.get("sub")):
        raise HTTPException(400, "Payment does not match this account")
    pay_id = _paid_payment_id(link) or req.razorpay_payment_id
    return _grant_pro(payload.get("sub"), pay_id, link.get("id"), link.get("amount"),
                      link.get("currency"), "callback")


# Razorpay rejects webhook URLs containing "razorpay" -> register this one in the dashboard.
@router.post("/api/billing/payment-webhook")
@router.post("/api/billing/razorpay/webhook")
async def webhook(request: Request):
    secret = (os.getenv("RAZORPAY_WEBHOOK_SECRET") or "").strip()
    if not secret:
        raise HTTPException(503, "Webhook not configured")
    raw = await request.body()
    sig = request.headers.get("x-razorpay-signature", "")
    expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(400, "Invalid signature")
    try:
        evt = json.loads(raw)
    except ValueError:
        raise HTTPException(400, "Bad payload")
    if evt.get("event") != "payment_link.paid":
        return {"ok": True, "ignored": evt.get("event")}
    pl = (evt.get("payload") or {})
    link = ((pl.get("payment_link") or {}).get("entity") or {})
    pay = ((pl.get("payment") or {}).get("entity") or {})
    user_id = (link.get("notes") or {}).get("user_id")
    if not user_id or not _link_matches(link, user_id) or not pay.get("id"):
        log.warning("razorpay webhook: link %s did not match a Pro purchase", link.get("id"))
        return {"ok": True, "ignored": "not a pro purchase"}
    res = _grant_pro(user_id, pay["id"], link.get("id"), link.get("amount"),
                     link.get("currency"), "webhook")
    return {"ok": True, **res}


def register(app):
    app.include_router(router)
