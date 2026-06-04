"""phishing_template_generate - Generate a generic phishing email template
(playbook §1 #7).

Returns the subject + HTML body of a parameterized phishing template,
based on options.template_type.  The template embeds three placeholders
the customer must replace before deploying to their internal authorized
phishing-simulation tooling:

  %TARGET_DOMAIN%   - the domain to impersonate (default: ScanRequest.target)
  %SENDER_DOMAIN%   - the lookalike domain the customer registered for
                      the simulation (default: "secure-<TARGET_DOMAIN>")
  %CALLBACK_URL%    - the URL the click should land on (defaults to a
                      mailto: placeholder so the template is inert if
                      shipped without customization)

NO sending happens — VulnusLab returns the template as a text artifact.
The customer wires it into their own GoPhish / King-Phisher / internal
mailer (which they run on their own attacker infrastructure) so the
spoofing emails count against their own SPF/DMARC posture, not ours.

Template catalogue (each is a 2024-2026-trending pretext):
  - password_expiry      (default) - "Your Microsoft 365 password expires in 24h"
  - mfa_enrollment        - "Enroll in new MFA before <date>"
  - shared_document       - "<colleague> shared a SharePoint document"
  - hr_payroll            - "Q4 payroll adjustment - verify your bank details"
  - it_helpdesk_ticket    - "Your IT ticket #<random> has been updated"
  - dropbox_share         - "You have a Dropbox file waiting"
  - docusign_signature    - "Please sign your document"
  - aws_ses_unverified    - "Action required: verify your AWS SES email"

INFO-only finding: includes the template, the rendered preview after
substituting the customer's domain into the placeholders, and a
remediation block about employee training + simulation cadence.

Customer input via ScanRequest.options:
  - template_type    = string, see list above (default "password_expiry")
  - sender_domain    = lookalike domain to splice into the From / link
  - callback_url     = URL the link should point at (customer-supplied)
"""
from __future__ import annotations
import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.phishing_template_generate_findings import (
    PHISHING_TEMPLATE_GENERATE_FINDING_RULES,
)

router = APIRouter()


class PhishingTemplateRequest(ScanRequest):
    options: Optional[dict] = None


# ─── Template catalogue (subject + html body) ─────────────────────────
# Placeholders use %NAME% so they're trivial to grep + replace and so
# the customer cannot accidentally render before customizing.

_TPL_PASSWORD_EXPIRY = {
    "subject": "Action required: Your %TARGET_DOMAIN% password expires in 24 hours",
    "html": (
        "<!doctype html><html><body style=\"font-family:Segoe UI,Arial,"
        "sans-serif;color:#222;\">\n"
        "<table width=\"600\" cellpadding=\"0\" cellspacing=\"0\" "
        "align=\"center\" style=\"border:1px solid #e1e1e1;border-radius:6px;"
        "padding:24px;\">\n"
        "<tr><td><img src=\"https://%SENDER_DOMAIN%/logo.png\" alt=\"\" "
        "width=\"140\"></td></tr>\n"
        "<tr><td style=\"padding:18px 0 6px 0;font-size:18px;\">"
        "<b>Your password for %TARGET_DOMAIN% expires in 24 hours.</b></td></tr>\n"
        "<tr><td style=\"font-size:14px;line-height:22px;padding:6px 0 14px 0;\">"
        "Hello,<br><br>\n"
        "Our system shows that your %TARGET_DOMAIN% account password is "
        "due to expire on <b>%EXPIRY_DATE%</b>. To avoid loss of access "
        "to your mailbox, calendar, and Teams files, please verify your "
        "current password and choose a new one using the link below."
        "</td></tr>\n"
        "<tr><td style=\"padding:8px 0;\">"
        "<a href=\"%CALLBACK_URL%\" style=\"background:#0078d4;color:#fff;"
        "padding:12px 22px;border-radius:4px;text-decoration:none;font-weight:600;\""
        ">Keep your current password</a></td></tr>\n"
        "<tr><td style=\"font-size:12px;color:#666;padding-top:14px;\">\n"
        "If you do not act within 24 hours your account will be locked.<br>\n"
        "%SENDER_DOMAIN% IT Helpdesk - automated notification - do not reply."
        "</td></tr></table></body></html>"
    ),
}

_TPL_MFA_ENROLL = {
    "subject": "Enroll in the new MFA for %TARGET_DOMAIN% by %EXPIRY_DATE%",
    "html": (
        "<!doctype html><html><body style=\"font-family:Segoe UI,Arial,"
        "sans-serif;color:#222;\">"
        "<p>Hi,</p>"
        "<p>We are rolling out a stronger MFA method for "
        "<b>%TARGET_DOMAIN%</b> accounts. Please complete enrollment "
        "before <b>%EXPIRY_DATE%</b> to avoid losing access.</p>"
        "<p><a href=\"%CALLBACK_URL%\">Enroll in new MFA</a></p>"
        "<p>%SENDER_DOMAIN% Identity Team</p></body></html>"
    ),
}

_TPL_SHARED_DOCUMENT = {
    "subject": "%SENDER_NAME% shared the document \"%DOC_NAME%\" with you",
    "html": (
        "<!doctype html><html><body style=\"font-family:Segoe UI,Arial,"
        "sans-serif;color:#222;\">"
        "<table width=\"560\" cellpadding=\"0\" cellspacing=\"0\" "
        "style=\"border:1px solid #ddd;padding:18px;\">"
        "<tr><td><b>%SENDER_NAME%</b> shared a document with you</td></tr>"
        "<tr><td style=\"padding:14px 0;font-size:18px;\">"
        "<a href=\"%CALLBACK_URL%\">%DOC_NAME%</a></td></tr>"
        "<tr><td style=\"font-size:12px;color:#666;\">"
        "This message was sent by %SENDER_DOMAIN% on behalf of %SENDER_NAME%. "
        "If you did not expect this message, you can safely ignore it."
        "</td></tr></table></body></html>"
    ),
}

_TPL_HR_PAYROLL = {
    "subject": "Important: Q4 payroll adjustment for %TARGET_DOMAIN% employees",
    "html": (
        "<!doctype html><html><body style=\"font-family:Segoe UI,Arial,"
        "sans-serif;color:#222;\">"
        "<p>Dear employee,</p>"
        "<p>HR has issued a payroll adjustment effective "
        "<b>%EXPIRY_DATE%</b>. To ensure correct deposit, please verify "
        "your direct-deposit details at:</p>"
        "<p><a href=\"%CALLBACK_URL%\">Verify bank account</a></p>"
        "<p>Failure to verify by %EXPIRY_DATE% may delay this month's "
        "deposit.</p>"
        "<p>%SENDER_DOMAIN% Human Resources</p></body></html>"
    ),
}

_TPL_IT_TICKET = {
    "subject": "[%TARGET_DOMAIN% IT] Your support ticket #%TICKET_ID% was updated",
    "html": (
        "<!doctype html><html><body style=\"font-family:Segoe UI,Arial,"
        "sans-serif;color:#222;\">"
        "<p>Hi,</p>"
        "<p>Your IT helpdesk ticket <b>#%TICKET_ID%</b> has a new "
        "response. Click the link below to read the technician's "
        "reply and confirm the issue is resolved.</p>"
        "<p><a href=\"%CALLBACK_URL%\">View ticket #%TICKET_ID%</a></p>"
        "<p>This ticket will auto-close in 48 hours if no response is "
        "received.</p>"
        "<p>%SENDER_DOMAIN% Service Desk</p></body></html>"
    ),
}

_TPL_DROPBOX = {
    "subject": "%SENDER_NAME% sent you a file via Dropbox",
    "html": (
        "<!doctype html><html><body style=\"font-family:Segoe UI,Arial,"
        "sans-serif;color:#222;\">"
        "<p><b>%SENDER_NAME%</b> sent you a file via Dropbox.</p>"
        "<p>File: <b>%DOC_NAME%</b><br>Expires: %EXPIRY_DATE%</p>"
        "<p><a href=\"%CALLBACK_URL%\">Open file</a></p>"
        "</body></html>"
    ),
}

_TPL_DOCUSIGN = {
    "subject": "%SENDER_NAME% requests your signature on \"%DOC_NAME%\"",
    "html": (
        "<!doctype html><html><body style=\"font-family:Segoe UI,Arial,"
        "sans-serif;color:#222;\">"
        "<p>Hello,</p>"
        "<p><b>%SENDER_NAME%</b> at %SENDER_DOMAIN% is waiting for your "
        "signature on the document <b>%DOC_NAME%</b>.</p>"
        "<p><a href=\"%CALLBACK_URL%\">Review and sign</a></p>"
        "</body></html>"
    ),
}

_TPL_AWS_SES = {
    "subject": "Action required: Verify your %TARGET_DOMAIN% AWS SES sender",
    "html": (
        "<!doctype html><html><body style=\"font-family:Segoe UI,Arial,"
        "sans-serif;color:#222;\">"
        "<p>Your %TARGET_DOMAIN% AWS SES sender identity is unverified. "
        "To avoid email delivery interruption, please complete "
        "verification at:</p>"
        "<p><a href=\"%CALLBACK_URL%\">Verify sender identity</a></p>"
        "<p>%SENDER_DOMAIN% AWS Notifications</p></body></html>"
    ),
}

TEMPLATES: dict[str, dict] = {
    "password_expiry":      _TPL_PASSWORD_EXPIRY,
    "mfa_enrollment":       _TPL_MFA_ENROLL,
    "shared_document":      _TPL_SHARED_DOCUMENT,
    "hr_payroll":           _TPL_HR_PAYROLL,
    "it_helpdesk_ticket":   _TPL_IT_TICKET,
    "dropbox_share":        _TPL_DROPBOX,
    "docusign_signature":   _TPL_DOCUSIGN,
    "aws_ses_unverified":   _TPL_AWS_SES,
}


def _normalize_domain(target: str) -> str:
    d = (target or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    if d.lower().startswith("www."):
        d = d[4:]
    return d.lower().rstrip(".")


def _render(template: dict, mapping: dict) -> dict:
    out = {}
    for k, v in template.items():
        rendered = v
        for ph, sub in mapping.items():
            rendered = rendered.replace(ph, sub)
        out[k] = rendered
    return out


async def gather(ctx: ScanContext):
    domain = _normalize_domain(ctx.host or "")
    if not domain:
        ctx.source("no-target")
        return

    opts = ctx.state.get("_options") or {}
    tpl_id = (opts.get("template_type") or "password_expiry").strip().lower()
    if tpl_id not in TEMPLATES:
        ctx.state["template_unknown"] = tpl_id
        ctx.state["template_supported"] = sorted(TEMPLATES.keys())
        ctx.source(f"unknown template_type={tpl_id}")
        # Fall back to default so we still produce an artifact
        tpl_id = "password_expiry"

    sender_domain = (opts.get("sender_domain") or
                     f"secure-{domain}").strip().lower()
    callback_url = (opts.get("callback_url") or
                    "mailto:CUSTOMIZE-BEFORE-USE@%SENDER_DOMAIN%").strip()

    # Per-template tactical fields
    expiry = (datetime.utcnow() + timedelta(hours=24)).strftime("%a, %d %b %Y")
    sender_name = (opts.get("sender_name") or "James Patterson").strip()
    doc_name = (opts.get("doc_name") or "Q4-Financial-Review.pdf").strip()
    ticket_id = (opts.get("ticket_id") or "INC-184327").strip()

    mapping = {
        "%TARGET_DOMAIN%": domain,
        "%SENDER_DOMAIN%": sender_domain,
        "%CALLBACK_URL%":  callback_url,
        "%EXPIRY_DATE%":   expiry,
        "%SENDER_NAME%":   sender_name,
        "%DOC_NAME%":      doc_name,
        "%TICKET_ID%":     ticket_id,
    }
    raw_template = TEMPLATES[tpl_id]
    rendered = _render(raw_template, mapping)
    ctx.state["template_id"] = tpl_id
    ctx.state["template_target_domain"] = domain
    ctx.state["template_sender_domain"] = sender_domain
    ctx.state["template_callback_url"] = callback_url
    ctx.state["template_raw"] = raw_template
    ctx.state["template_rendered"] = rendered
    ctx.state["template_placeholders_used"] = sorted(
        ph for ph in mapping if ph in (raw_template.get("subject", "") + raw_template.get("html", ""))
    )
    ctx.state["template_supported"] = sorted(TEMPLATES.keys())
    ctx.state["template_subject_preview"] = rendered.get("subject", "")
    ctx.state["template_html_byte_len"] = len(rendered.get("html", "").encode("utf-8"))
    # Also include a small JSON "kit" the customer can import directly
    # into GoPhish / King-Phisher.
    ctx.state["template_export_json"] = json.dumps({
        "id":            tpl_id,
        "subject":       rendered["subject"],
        "html":          rendered["html"],
        "placeholders":  mapping,
    }, ensure_ascii=False, indent=2)
    ctx.source(
        f"template={tpl_id} rendered "
        f"(subject={len(rendered.get('subject', ''))}c, "
        f"html={ctx.state['template_html_byte_len']}B)"
    )


INTEL_FIELDS = [
    ("Template id",           "template_id"),
    ("Target domain",         "template_target_domain"),
    ("Sender (spoof) domain", "template_sender_domain"),
    ("Callback URL",          "template_callback_url"),
    ("Supported templates",   "template_supported"),
    ("Subject (rendered)",    "template_subject_preview"),
    ("HTML body size",        "template_html_byte_len"),
    ("Placeholders used",     "template_placeholders_used"),
    ("Rendered template",     "template_rendered"),
    ("Export JSON kit",       "template_export_json"),
]


@router.post("/api/phishing/phishing_template_generate")
async def phishing_phishing_template_generate(req: PhishingTemplateRequest,
                                                _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="phishing_template_generate",
        gather_func=_gather_with_options,
        finding_rules=PHISHING_TEMPLATE_GENERATE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
