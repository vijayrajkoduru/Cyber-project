"""Razorpay REST + signature helpers (stdlib hmac/hashlib + requests only).

Credentials come from env:
  RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET

Until those are set, is_configured() returns False and the payment endpoints
respond 503 — so the platform boots fine with empty/placeholder keys.
"""
from __future__ import annotations

import hashlib
import hmac
import os

import requests

API_BASE = "https://api.razorpay.com/v1"
_TIMEOUT = 20


def key_id() -> str:
    return os.getenv("RAZORPAY_KEY_ID", "").strip()


def _key_secret() -> str:
    return os.getenv("RAZORPAY_KEY_SECRET", "").strip()


def _webhook_secret() -> str:
    return os.getenv("RAZORPAY_WEBHOOK_SECRET", "").strip()


def is_configured() -> bool:
    return bool(key_id() and _key_secret())


def create_order(amount: int, currency: str, receipt: str, notes: dict) -> dict:
    """Create a Razorpay order; returns the order JSON (incl. 'id'). Raises on HTTP error."""
    resp = requests.post(
        f"{API_BASE}/orders",
        auth=(key_id(), _key_secret()),
        json={
            "amount": int(amount),
            "currency": currency,
            "receipt": (receipt or "vl")[:40],
            "notes": notes or {},
            "payment_capture": 1,
        },
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_order(order_id: str) -> dict:
    """Fetch an order (used to recover notes when a webhook entity omits them)."""
    resp = requests.get(
        f"{API_BASE}/orders/{order_id}",
        auth=(key_id(), _key_secret()),
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def verify_payment_signature(order_id: str, payment_id: str, signature: str) -> bool:
    """Client-callback signature: HMAC_SHA256("order_id|payment_id", key_secret)."""
    secret = _key_secret().encode()
    if not secret or not signature or not order_id or not payment_id:
        return False
    expected = hmac.new(secret, f"{order_id}|{payment_id}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_webhook_signature(raw_body: bytes, signature: str) -> bool:
    """Webhook signature: HMAC_SHA256(raw_request_body, webhook_secret)."""
    secret = _webhook_secret().encode()
    if not secret or not signature:
        return False
    expected = hmac.new(secret, raw_body or b"", hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
