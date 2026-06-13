"""Transactional email — provider-agnostic (SendGrid / ZeptoMail / SMTP).

Env:
  EMAIL_PROVIDER = sendgrid | zeptomail | smtp   (unset -> emails are logged, not sent)
  EMAIL_API_KEY  = <api key>                      (sendgrid / zeptomail)
  EMAIL_FROM     = no-reply@vulnuslab.com
  EMAIL_REPLY_TO = support@vulnuslab.com
  # SMTP only:
  EMAIL_SMTP_HOST, EMAIL_SMTP_PORT (default 587), EMAIL_SMTP_USER, EMAIL_SMTP_PASS

send_email() never raises — a mail failure must never roll back a paid account.
"""
from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email.mime.text import MIMEText

import requests

_log = logging.getLogger("vulnuslab.mailer")


def _from():     return os.getenv("EMAIL_FROM", "no-reply@vulnuslab.com").strip()
def _reply_to(): return os.getenv("EMAIL_REPLY_TO", "support@vulnuslab.com").strip()
def _provider(): return os.getenv("EMAIL_PROVIDER", "").strip().lower()


def is_configured() -> bool:
    p = _provider()
    if p in ("sendgrid", "zeptomail"):
        return bool(os.getenv("EMAIL_API_KEY", "").strip())
    if p == "smtp":
        return bool(os.getenv("EMAIL_SMTP_HOST", "").strip())
    return False


def send_email(to: str, subject: str, html: str) -> bool:
    """Send one HTML email. Returns True on success. Never raises."""
    if not to:
        return False
    p = _provider()
    try:
        if p == "sendgrid":
            return _send_sendgrid(to, subject, html)
        if p == "zeptomail":
            return _send_zeptomail(to, subject, html)
        if p == "smtp":
            return _send_smtp(to, subject, html)
        _log.warning("EMAIL_PROVIDER not set — email to %s NOT sent (subject: %s)", to, subject)
        return False
    except Exception as exc:
        _log.error("send_email to %s failed: %s", to, exc)
        return False


def _send_sendgrid(to, subject, html) -> bool:
    r = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={"Authorization": "Bearer " + os.getenv("EMAIL_API_KEY", ""),
                 "Content-Type": "application/json"},
        json={"personalizations": [{"to": [{"email": to}]}],
              "from": {"email": _from(), "name": "VulnusLab"},
              "reply_to": {"email": _reply_to()},
              "subject": subject,
              "content": [{"type": "text/html", "value": html}]},
        timeout=20,
    )
    ok = r.status_code in (200, 201, 202)
    if not ok:
        _log.error("sendgrid %s: %s", r.status_code, r.text[:300])
    return ok


def _send_zeptomail(to, subject, html) -> bool:
    key = os.getenv("EMAIL_API_KEY", "")
    payload = {"from": {"address": _from(), "name": "VulnusLab"},
               "to": [{"email_address": {"address": to}}],
               "reply_to": [{"address": _reply_to()}],
               "subject": subject, "htmlbody": html}
    # .in for India-region ZeptoMail accounts; fall back to .com.
    for host in ("https://api.zeptomail.in/v1.1/email", "https://api.zeptomail.com/v1.1/email"):
        try:
            r = requests.post(host, headers={"Authorization": key, "Content-Type": "application/json"},
                              json=payload, timeout=20)
            if r.status_code in (200, 201, 202):
                return True
            _log.error("zeptomail %s %s: %s", host, r.status_code, r.text[:300])
        except Exception as exc:
            _log.error("zeptomail %s error: %s", host, exc)
    return False


def _send_smtp(to, subject, html) -> bool:
    host = os.getenv("EMAIL_SMTP_HOST", "")
    port = int(os.getenv("EMAIL_SMTP_PORT", "587") or "587")
    user = os.getenv("EMAIL_SMTP_USER", "")
    pw = os.getenv("EMAIL_SMTP_PASS", "")
    msg = MIMEText(html, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = _from()
    msg["To"] = to
    msg["Reply-To"] = _reply_to()
    ctx = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=20) as s:
        s.starttls(context=ctx)
        if user:
            s.login(user, pw)
        s.sendmail(_from(), [to], msg.as_string())
    return True


# ── Templates ────────────────────────────────────────────────────────
def _money(amount, currency="USD"):
    cur = (currency or "USD").upper()
    sym = {"INR": "₹", "USD": "$"}.get(cur, cur + " ")
    try:
        return f"{sym}{int(amount) / 100:,.2f}"
    except Exception:
        return f"{sym}{amount}"


def _shell(body_html: str) -> str:
    return f"""<!DOCTYPE html><html><body style="margin:0;background:#f4f6fb;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#1f2937">
  <div style="max-width:560px;margin:0 auto;padding:28px 20px">
    <div style="font-size:20px;font-weight:800;margin-bottom:18px">VULNUS<span style="color:#2563eb">LAB</span></div>
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:26px 28px;line-height:1.7;font-size:15px">
      {body_html}
    </div>
    <p style="color:#9aa3b2;font-size:12px;margin-top:18px">VulnusLab — Automated Vulnerability Assessment Platform · <a href="https://vulnuslab.com" style="color:#2563eb;text-decoration:none">vulnuslab.com</a> · support@vulnuslab.com</p>
  </div></body></html>"""


def welcome_html(name, username, plan_label, temp_password, dashboard_url):
    if temp_password:
        creds = (f"<p style='margin:14px 0;padding:14px 16px;background:#f0f5ff;border:1px solid #d6e4ff;border-radius:8px'>"
                 f"<b>Username:</b> {username}<br><b>Temporary password:</b> "
                 f"<code style='font-size:15px'>{temp_password}</code><br>"
                 f"<span style='color:#6b7280;font-size:13px'>Please change your password after first sign-in.</span></p>")
    else:
        creds = (f"<p style='margin:14px 0'>Your existing account (<b>{username}</b>) has been upgraded — "
                 f"sign in with your current password.</p>")
    return _shell(
        f"<h2 style='margin:0 0 10px;font-size:20px'>Welcome to VulnusLab, {name}</h2>"
        f"<p>Your payment was successful and your <b>{plan_label}</b> plan is now active.</p>"
        f"{creds}"
        f"<p style='margin:22px 0'><a href='{dashboard_url}' style='background:#2563eb;color:#fff;text-decoration:none;"
        f"padding:11px 22px;border-radius:8px;font-weight:700;display:inline-block'>Open your dashboard</a></p>"
        f"<p style='color:#6b7280;font-size:13px'>Reminder: only scan systems you own or are explicitly authorized to test.</p>")


def receipt_html(name, plan_label, amount_paise, payment_id, currency="INR"):
    return _shell(
        f"<h2 style='margin:0 0 10px;font-size:20px'>Payment receipt</h2>"
        f"<p>Thank you, {name}. Here is your receipt.</p>"
        f"<table style='width:100%;border-collapse:collapse;margin-top:12px;font-size:14px'>"
        f"<tr><td style='padding:8px 0;color:#6b7280'>Plan</td><td style='text-align:right;font-weight:700'>{plan_label}</td></tr>"
        f"<tr><td style='padding:8px 0;color:#6b7280'>Amount</td><td style='text-align:right;font-weight:700'>{_money(amount_paise, currency)}</td></tr>"
        f"<tr><td style='padding:8px 0;color:#6b7280'>Payment ID</td><td style='text-align:right;font-family:monospace'>{payment_id}</td></tr>"
        f"</table>"
        f"<p style='color:#6b7280;font-size:13px;margin-top:18px'>Questions about billing? Reply to this email or contact "
        f"<a href='mailto:support@vulnuslab.com' style='color:#2563eb'>support@vulnuslab.com</a>.</p>")
