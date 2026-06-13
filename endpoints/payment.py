"""Razorpay payments — order creation, signed webhook, client verify, config.

Flow:
  1. Checkout page GETs /api/payment/config            -> key_id + plan list
  2. POSTs /api/payment/create-order {plan_id,name,email} -> Razorpay order_id
  3. Razorpay Checkout.js collects the payment (we never touch card data)
  4. Razorpay calls /api/payment/webhook (HMAC-signed)  -> provision user + email
  5. Browser POSTs /api/payment/verify (signature)      -> success UX only

Provisioning is driven by the WEBHOOK (server-side, unforgeable), not the
browser callback. Boots fine without keys: when Razorpay isn't configured,
create-order returns 503 and the webhook rejects unsigned calls.
"""
from __future__ import annotations

import json
import logging
import os

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from tools._payments import mailer
from tools._payments import razorpay_client as rzp
from tools._payments.plans import get_plan, public_plans
from tools._payments.provisioning import provision_paid_user

_log = logging.getLogger("vulnuslab.payment")
router = APIRouter()

_PAID_EVENTS = ("payment.captured", "order.paid")


def _dashboard_url() -> str:
    return os.getenv("DASHBOARD_URL", "https://app.vulnuslab.com").strip()


@router.get("/api/payment/config")
async def payment_config():
    """Public: tells the checkout page whether payments are live + the plans."""
    configured = rzp.is_configured()
    return {
        "configured": configured,
        "key_id": rzp.key_id() if configured else "",
        "plans": public_plans(),
    }


class CreateOrderRequest(BaseModel):
    plan_id: str
    email: str
    name: str = ""


@router.post("/api/payment/create-order")
async def create_order(req: CreateOrderRequest):
    if not rzp.is_configured():
        raise HTTPException(503, "Payments are not configured yet")
    plan = get_plan(req.plan_id)
    if not plan:
        raise HTTPException(400, "Unknown plan")
    email = (req.email or "").strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(400, "A valid email is required")
    try:
        order = rzp.create_order(
            amount=plan["amount"],
            currency=plan["currency"],
            receipt=f"vl_{req.plan_id}",
            notes={"plan_id": req.plan_id, "customer_email": email,
                   "customer_name": (req.name or "")[:100]},
        )
    except Exception as exc:
        _log.error("create_order failed: %s", exc)
        raise HTTPException(502, "Could not create payment order")
    return {
        "order_id": order.get("id"),
        "amount": plan["amount"],
        "currency": plan["currency"],
        "key_id": rzp.key_id(),
        "plan_id": req.plan_id,
        "plan_label": plan["label"],
        "name": req.name,
        "email": email,
    }


class VerifyRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str


@router.post("/api/payment/verify")
async def verify(req: VerifyRequest):
    """Client-callback verification — UX only. Provisioning happens in the webhook."""
    ok = rzp.verify_payment_signature(
        req.razorpay_order_id, req.razorpay_payment_id, req.razorpay_signature)
    return {"verified": bool(ok)}


def _extract_notes(payment: dict, order: dict) -> dict:
    notes = payment.get("notes") or order.get("notes") or {}
    if (not notes or not notes.get("plan_id")):
        oid = payment.get("order_id") or order.get("id")
        if oid and rzp.is_configured():
            try:
                notes = (rzp.fetch_order(oid) or {}).get("notes") or notes
            except Exception as exc:
                _log.warning("fetch_order(%s) for notes failed: %s", oid, exc)
    return notes or {}


@router.post("/api/payment/webhook")
async def webhook(request: Request):
    raw = await request.body()
    sig = request.headers.get("X-Razorpay-Signature", "")
    if not rzp.verify_webhook_signature(raw, sig):
        raise HTTPException(400, "Invalid webhook signature")
    try:
        event = json.loads(raw.decode("utf-8", errors="ignore"))
    except Exception:
        raise HTTPException(400, "Bad payload")

    etype = event.get("event", "")
    if etype not in _PAID_EVENTS:
        return {"ok": True, "ignored": etype}

    payload = event.get("payload") or {}
    payment = ((payload.get("payment") or {}).get("entity")) or {}
    order = ((payload.get("order") or {}).get("entity")) or {}
    notes = _extract_notes(payment, order)

    plan = get_plan(notes.get("plan_id"))
    email = (notes.get("customer_email") or payment.get("email") or "").strip().lower()
    name = notes.get("customer_name") or (email.split("@")[0] if email else "there")
    if not plan or not email:
        _log.warning("webhook %s: missing plan/email (plan_id=%s email=%s)",
                     etype, notes.get("plan_id"), email)
        return {"ok": True, "skipped": "missing plan/email"}

    payment_id = payment.get("id") or order.get("id") or ""
    order_id = payment.get("order_id") or order.get("id") or ""
    amount = payment.get("amount") or order.get("amount") or plan["amount"]
    currency = payment.get("currency") or plan["currency"]

    try:
        result = provision_paid_user(
            email=email, name=name, plan_key=plan["plan"], plan_label=plan["label"],
            period_days=plan["period_days"], payment_id=payment_id, order_id=order_id,
            amount=amount, currency=currency,
        )
    except Exception as exc:
        _log.error("provisioning failed for %s: %s", email, exc)
        raise HTTPException(500, "provisioning error")

    if result.get("already_processed"):
        return {"ok": True, "duplicate": True}

    # Welcome + receipt (best-effort; never roll back a paid account on mail error).
    try:
        mailer.send_email(
            email, "Welcome to VulnusLab — your account is ready",
            mailer.welcome_html(name, result["username"], plan["label"],
                                result.get("temp_password"), _dashboard_url()))
        mailer.send_email(
            email, "Your VulnusLab payment receipt",
            mailer.receipt_html(name, plan["label"], amount, payment_id, currency))
    except Exception as exc:
        _log.error("post-provision email failed for %s: %s", email, exc)

    return {"ok": True, "created": result.get("created")}


def register(app):
    app.include_router(router)
