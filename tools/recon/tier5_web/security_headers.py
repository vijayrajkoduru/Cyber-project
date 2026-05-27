"""security_headers — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    url = base_url(ctx.host)
    code, hdrs, _ = await fetch(url)
    lh = {k.lower(): v for k,v in hdrs.items()}
    missing = []
    for h_name in ("content-security-policy","x-content-type-options","x-frame-options",
                   "strict-transport-security","referrer-policy","permissions-policy"):
        if h_name not in lh: missing.append(h_name)
    ctx.state["headers_present"] = list(lh.keys())
    ctx.state["missing_headers"] = missing
    ctx.source("HTTP response header audit")

RULES = [
    lambda s: {"name":"Missing Content-Security-Policy header","severity":"MEDIUM",
        "evidence":"No CSP header — XSS mitigation absent",
        "remediation":"Add CSP header, e.g. \"default-src 'self'; script-src 'self'\"",
        "cwe":"CWE-693","owasp":"A05:2021"
    } if "content-security-policy" in s.get("missing_headers",[]) else None,
    lambda s: {"name":"Missing Strict-Transport-Security (HSTS)","severity":"MEDIUM",
        "evidence":"No HSTS header — downgrade attacks possible",
        "remediation":"Add HSTS: \"max-age=31536000; includeSubDomains; preload\"",
        "cwe":"CWE-319","owasp":"A02:2021"
    } if "strict-transport-security" in s.get("missing_headers",[]) else None,
    lambda s: {"name":"Missing X-Frame-Options","severity":"LOW",
        "evidence":"No X-Frame-Options header — clickjacking possible",
        "remediation":"Add X-Frame-Options: DENY (or use CSP frame-ancestors)",
        "cwe":"CWE-1021","owasp":"A05:2021"
    } if "x-frame-options" in s.get("missing_headers",[]) else None,
    lambda s: {"name":"Missing X-Content-Type-Options","severity":"LOW",
        "evidence":"No X-Content-Type-Options header — MIME sniffing possible",
        "remediation":"Add X-Content-Type-Options: nosniff",
        "cwe":"CWE-693","owasp":"A05:2021"
    } if "x-content-type-options" in s.get("missing_headers",[]) else None,
]

@router.post("/api/recon/security_headers")
async def recon_security_headers(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="security_headers",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Headers Present","headers_present"),("Missing Headers","missing_headers")])

def register(app):
    app.include_router(router)
