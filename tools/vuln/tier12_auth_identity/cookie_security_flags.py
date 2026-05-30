"""Cookie security flags audit (Secure/HttpOnly/SameSite). VL-FORGE Vuln tier12 - §12 #185."""
import asyncio
import ssl
import urllib.request
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import run_scanner

router = APIRouter()
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


def _cookies(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (VulnusLab Vuln)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            return r.headers.get_all("Set-Cookie") or []
    except Exception as e:
        h = getattr(e, "headers", None)
        return (h.get_all("Set-Cookie") or []) if h else []


async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    cookies = await asyncio.to_thread(_cookies, base + "/")
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["cookie_count"] = len(cookies)
    issues = []
    for c in cookies:
        name = c.split("=", 1)[0].strip()
        cl = c.lower()
        miss = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in cl]
        if miss:
            issues.append(f"{name}: missing {', '.join(miss)}")
    if issues:
        ctx.state["cookie_issues"] = issues


def _r_issues(s):
    iss = s.get("cookie_issues") or []
    if not iss:
        return None
    crit = any(("HttpOnly" in i or "Secure" in i) for i in iss)
    return {"name": f"Cookies missing security flags ({len(iss)})", "severity": "MEDIUM" if crit else "LOW",
            "cvss": 5.3 if crit else 3.1, "cwe": "CWE-1004",
            "evidence": "; ".join(iss[:6]),
            "remediation": "Set Secure + HttpOnly + SameSite=Lax/Strict on session cookies."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or s.get("cookie_issues"):
        return None
    return {"name": "Cookie security flags OK", "severity": "POSITIVE",
            "evidence": f"{s.get('cookie_count', 0)} cookie(s); none missing Secure/HttpOnly/SameSite."}


FINDING_RULES = [_r_issues, _r_clean]
INTEL_FIELDS = [("Cookies set", "cookie_count")]


@router.post("/api/vuln/cookie_security_flags")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="cookie_security_flags",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
