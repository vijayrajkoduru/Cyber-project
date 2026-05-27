"""email_smtp_validate — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text
import smtplib, dns.resolver, socket

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    try:
        mx_recs = await asyncio.to_thread(dns.resolver.resolve, h, "MX", lifetime=5)
        mx_host = str(sorted(mx_recs, key=lambda r: r.preference)[0].exchange).rstrip(".")
    except Exception:
        ctx.state["mx_resolved"] = False; ctx.source("No MX records"); return
    catchall = False; banner = ""
    def _probe():
        try:
            s = smtplib.SMTP(mx_host, 25, timeout=8); s.set_debuglevel(0)
            s.helo("vulnuslab.com")
            code1, _ = s.mail(f"audit@vulnuslab.com")
            code2, _ = s.rcpt(f"this-very-unlikely-mailbox-83fjk2@{h}")
            return code1, code2, s.sock.getpeername() if s.sock else None
        except Exception as e: return 0, 0, str(e)[:120]
    res = await asyncio.to_thread(_probe)
    ctx.state["mx_resolved"] = True
    ctx.state["mx_host"] = mx_host
    ctx.state["mail_code"] = res[0]; ctx.state["rcpt_code"] = res[1]
    ctx.state["catchall_suspected"] = res[1] == 250
    ctx.source("SMTP RCPT TO with unlikely mailbox")

RULES = [
    lambda s: {"name":"SMTP server accepts catch-all addresses (deliverability + verification risk)","severity":"LOW",
        "evidence":f"RCPT TO unlikely-mailbox@{s.get('mx_host','')} returned 250",
        "remediation":"Configure MTA to reject invalid recipients (550). Catch-all enables email-validation bypass attacks.",
        "cwe":"CWE-203","owasp":"N/A"
    } if s.get("catchall_suspected") else None,
]

@router.post("/api/recon/email_smtp_validate")
async def recon_email_smtp_validate(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="email_smtp_validate",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("MX Resolved","mx_resolved"),("MX Host","mx_host"),("Catchall Suspected","catchall_suspected")])

def register(app):
    app.include_router(router)
