"""Razorpay payments — order creation, signed webhook, client verify, config.

Two purchase shapes share one flow:
  - À LA CARTE (primary): customer picks module ids -> monthly subscription to
    exactly those modules (tools/_payments/module_catalog.py + entitlements).
  - PLAN (legacy/optional): a single plan_id -> tools/_payments/plans.py.

Flow:
  1. Checkout GETs /api/payment/config            -> key_id + modules + plans
  2. POSTs /api/payment/create-order              -> Razorpay order (amount is
     computed SERVER-SIDE from the catalogue; the client total is never trusted)
  3. Razorpay Checkout.js collects the payment (we never touch card data)
  4. Razorpay calls /api/payment/webhook (HMAC-signed) -> provision + email
  5. Browser POSTs /api/payment/verify (signature)     -> success UX only

Boots fine without keys: create-order returns 503, the webhook rejects unsigned.
"""
from __future__ import annotations

import json
import logging
import os
from typing import List

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from tools._payments import mailer
from tools._payments import razorpay_client as rzp
from tools._payments.module_catalog import (CURRENCY, MODULE_PERIOD_DAYS,
                                             get_module, price_for,
                                             public_modules, valid_ids)
from tools._payments.plans import get_plan, public_plans
from tools._payments.provisioning import (provision_module_purchase,
                                          provision_paid_user)

_log = logging.getLogger("vulnuslab.payment")
router = APIRouter()

_PAID_EVENTS = ("payment.captured", "order.paid")


def _dashboard_url() -> str:
    return os.getenv("DASHBOARD_URL", "https://app.vulnuslab.com").strip()


def _valid_email(email: str) -> bool:
    email = (email or "").strip().lower()
    return "@" in email and "." in email.split("@")[-1]


@router.get("/api/payment/config")
async def payment_config():
    """Public: whether payments are live + the module catalogue + legacy plans."""
    configured = rzp.is_configured()
    return {
        "configured": configured,
        "key_id": rzp.key_id() if configured else "",
        "currency": CURRENCY,
        "modules": public_modules(),
        "plans": public_plans(),
        "period_days": MODULE_PERIOD_DAYS,
    }


class CreateOrderRequest(BaseModel):
    email: str
    name: str = ""
    module_ids: List[str] = []
    plan_id: str = ""


@router.post("/api/payment/create-order")
async def create_order(req: CreateOrderRequest):
    if not rzp.is_configured():
        raise HTTPException(503, "Payments are not configured yet")
    email = (req.email or "").strip().lower()
    if not _valid_email(email):
        raise HTTPException(400, "A valid email is required")
    name = (req.name or "")[:100]

    # ── À la carte modules (primary path) ──
    mids = valid_ids(req.module_ids)
    if mids:
        amount = price_for(mids)             # server-computed; client total ignored
        if amount <= 0:
            raise HTTPException(400, "Selected modules have no price configured")
        labels = ", ".join(get_module(m)["label"] for m in mids)
        try:
            order = rzp.create_order(
                amount=amount, currency=CURRENCY, receipt="vl_modules",
                notes={"kind": "modules", "module_ids": ",".join(mids),
                       "customer_email": email, "customer_name": name})
        except Exception as exc:
            _log.error("create_order (modules) failed: %s", exc)
            raise HTTPException(502, "Could not create payment order")
        return {"order_id": order.get("id"), "amount": amount, "currency": CURRENCY,
                "key_id": rzp.key_id(), "kind": "modules", "module_ids": mids,
                "label": f"Modules: {labels}", "name": name, "email": email}

    # ── Legacy single plan ──
    plan = get_plan(req.plan_id)
    if plan:
        try:
            order = rzp.create_order(
                amount=plan["amount"], currency=plan["currency"], receipt=f"vl_{req.plan_id}",
                notes={"kind": "plan", "plan_id": req.plan_id,
                       "customer_email": email, "customer_name": name})
        except Exception as exc:
            _log.error("create_order (plan) failed: %s", exc)
            raise HTTPException(502, "Could not create payment order")
        return {"order_id": order.get("id"), "amount": plan["amount"], "currency": plan["currency"],
                "key_id": rzp.key_id(), "kind": "plan", "plan_id": req.plan_id,
                "label": plan["label"], "name": name, "email": email}

    raise HTTPException(400, "Select at least one module to subscribe to")


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
    if not notes or not (notes.get("kind") or notes.get("plan_id") or notes.get("module_ids")):
        oid = payment.get("order_id") or order.get("id")
        if oid and rzp.is_configured():
            try:
                notes = (rzp.fetch_order(oid) or {}).get("notes") or notes
            except Exception as exc:
                _log.warning("fetch_order(%s) for notes failed: %s", oid, exc)
    return notes or {}


def _send_account_emails(email, name, username, label, temp_password, amount, currency, payment_id):
    try:
        mailer.send_email(
            email, "Welcome to VulnusLab — your account is ready",
            mailer.welcome_html(name, username, label, temp_password, _dashboard_url()))
        mailer.send_email(
            email, "Your VulnusLab payment receipt",
            mailer.receipt_html(name, label, amount, payment_id, currency))
    except Exception as exc:
        _log.error("post-provision email failed for %s: %s", email, exc)


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

    if event.get("event", "") not in _PAID_EVENTS:
        return {"ok": True, "ignored": event.get("event", "")}

    payload = event.get("payload") or {}
    payment = ((payload.get("payment") or {}).get("entity")) or {}
    order = ((payload.get("order") or {}).get("entity")) or {}
    notes = _extract_notes(payment, order)

    email = (notes.get("customer_email") or payment.get("email") or "").strip().lower()
    name = notes.get("customer_name") or (email.split("@")[0] if email else "there")
    payment_id = payment.get("id") or order.get("id") or ""
    order_id = payment.get("order_id") or order.get("id") or ""
    amount = payment.get("amount") or order.get("amount") or 0
    currency = payment.get("currency") or "INR"

    kind = notes.get("kind") or ("modules" if notes.get("module_ids") else "plan")

    # ── À la carte modules ──
    if kind == "modules":
        mids = valid_ids((notes.get("module_ids") or "").split(","))
        if not mids or not email:
            _log.warning("webhook: missing modules/email (ids=%s email=%s)",
                         notes.get("module_ids"), email)
            return {"ok": True, "skipped": "missing modules/email"}
        try:
            result = provision_module_purchase(
                email=email, name=name, module_ids=mids, days=MODULE_PERIOD_DAYS,
                payment_id=payment_id, order_id=order_id, amount=amount, currency=currency)
        except Exception as exc:
            _log.error("module provisioning failed for %s: %s", email, exc)
            raise HTTPException(500, "provisioning error")
        if result.get("already_processed"):
            return {"ok": True, "duplicate": True}
        label = "Modules: " + ", ".join(get_module(m)["label"] for m in mids)
        _send_account_emails(email, name, result["username"], label,
                             result.get("temp_password"), amount, currency, payment_id)
        return {"ok": True, "created": result.get("created"), "modules": mids}

    # ── Legacy plan ──
    plan = get_plan(notes.get("plan_id"))
    if not plan or not email:
        _log.warning("webhook: missing plan/email (plan_id=%s email=%s)",
                     notes.get("plan_id"), email)
        return {"ok": True, "skipped": "missing plan/email"}
    if not amount:
        amount = plan["amount"]
    try:
        result = provision_paid_user(
            email=email, name=name, plan_key=plan["plan"], plan_label=plan["label"],
            period_days=plan["period_days"], payment_id=payment_id, order_id=order_id,
            amount=amount, currency=currency)
    except Exception as exc:
        _log.error("plan provisioning failed for %s: %s", email, exc)
        raise HTTPException(500, "provisioning error")
    if result.get("already_processed"):
        return {"ok": True, "duplicate": True}
    _send_account_emails(email, name, result["username"], plan["label"],
                         result.get("temp_password"), amount, currency, payment_id)
    return {"ok": True, "created": result.get("created")}


def register(app):
    app.include_router(router)
