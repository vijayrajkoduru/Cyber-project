"""Transactional email — ZeptoMail (Zoho) HTTP API, dependency-free.

Degrades gracefully: if EMAIL_API_KEY is unset it logs and returns False
instead of raising, so dev/CI and unconfigured deploys never break the flow
that triggered the email (e.g. registration still succeeds).

Env: EMAIL_PROVIDER=zeptomail · EMAIL_API_KEY=Zoho-enczapikey ... ·
     EMAIL_FROM=no-reply@vulnuslab.com · EMAIL_REPLY_TO=support@vulnuslab.com
     APP_BASE_URL=https://app.vulnuslab.com  (used to build links)
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request

log = logging.getLogger("vulnuslab.email")

_ZEPTO_URL = "https://api.zeptomail.com/v1.1/email"


def app_base_url() -> str:
    return os.getenv("APP_BASE_URL", "https://app.vulnuslab.com").rstrip("/")


def send_email(to: str, subject: str, html: str, *, text: str | None = None) -> bool:
    """Send one email. Returns True on success, False if unconfigured/failed.
    Never raises."""
    api_key = os.getenv("EMAIL_API_KEY", "").strip()
    sender = os.getenv("EMAIL_FROM", "no-reply@vulnuslab.com")
    if not api_key:
        log.warning("EMAIL_API_KEY unset — skipping email to %s (subject=%r)", to, subject)
        return False
    if os.getenv("EMAIL_PROVIDER", "zeptomail").lower() != "zeptomail":
        log.warning("EMAIL_PROVIDER not zeptomail — no other provider wired yet")
        return False
    payload = {
        "from": {"address": sender},
        "to": [{"email_address": {"address": to}}],
        "subject": subject,
        "htmlbody": html,
    }
    reply_to = os.getenv("EMAIL_REPLY_TO", "")
    if reply_to:
        payload["reply_to"] = [{"address": reply_to}]
    if text:
        payload["textbody"] = text
    # ZeptoMail expects the key verbatim ("Zoho-enczapikey ...") as Authorization.
    auth = api_key if api_key.lower().startswith("zoho-") else f"Zoho-enczapikey {api_key}"
    req = urllib.request.Request(
        _ZEPTO_URL, data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": auth, "Content-Type": "application/json",
                 "Accept": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            ok = 200 <= resp.status < 300
            if not ok:
                log.warning("email send to %s returned HTTP %s", to, resp.status)
            return ok
    except Exception as exc:
        log.warning("email send to %s failed: %s", to, exc)
        return False


def send_verification_email(to: str, token: str) -> bool:
    link = f"{app_base_url()}/verify-email?token={token}"
    html = (f"<p>Welcome to VulnusLab. Please confirm your email:</p>"
            f'<p><a href="{link}">Verify my email</a></p>'
            f"<p>Or paste this link: {link}</p>"
            f"<p>This link expires in 48 hours.</p>")
    return send_email(to, "Verify your VulnusLab email", html,
                      text=f"Verify your email: {link}")


def send_welcome_email(to: str, username: str, plan: str, verify_token: str | None = None) -> bool:
    """Onboarding email sent at signup: greets the customer, states their plan,
    and (optionally) includes the email-verification link in the same message."""
    plan_label = (plan or "trial").capitalize()
    verify_block = ""
    if verify_token:
        link = f"{app_base_url()}/verify-email?token={verify_token}"
        verify_block = (f'<p>First, confirm your email: '
                        f'<a href="{link}">Verify my email</a><br>'
                        f"<span style=\"color:#888\">{link}</span></p>")
    html = (f"<h2>Welcome to VulnusLab, {username}!</h2>"
            f"<p>Your account is ready. Current plan: <b>{plan_label}</b>.</p>"
            f"{verify_block}"
            f'<p>Sign in: <a href="{app_base_url()}">{app_base_url()}</a></p>'
            f"<p>Run your first scan from the dashboard, then download the PDF report.</p>"
            f"<p>Questions? Reply to this email.</p>")
    return send_email(to, f"Welcome to VulnusLab — {plan_label} plan", html,
                      text=f"Welcome {username}! Plan: {plan_label}. Sign in: {app_base_url()}")
