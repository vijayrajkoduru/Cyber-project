"""security_txt — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    found = False; loc = ""; contact = ""
    for path in ("/.well-known/security.txt","/security.txt"):
        code, _, body = await fetch(f"{base}{path}")
        if code == 200 and b"Contact:" in body:
            found = True; loc = path
            t = body.decode("utf-8","ignore")
            m = re.search(r"(?i)^Contact:\s*(.+)$", t, re.M)
            if m: contact = m.group(1).strip()
            break
    ctx.state["security_txt_found"] = found
    ctx.state["location"] = loc
    ctx.state["contact"] = contact
    ctx.source("/.well-known/security.txt + /security.txt probe")

RULES = [
    lambda s: {"name":"Missing security.txt","severity":"LOW",
        "evidence":"No /.well-known/security.txt — no public security contact for vulnerability reports",
        "remediation":"Publish security.txt per RFC 9116 with Contact + Expires fields",
        "cwe":"N/A","owasp":"N/A"
    } if not s.get("security_txt_found") else None,
]

@router.post("/api/recon/security_txt")
async def recon_security_txt(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="security_txt",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Security TXT Found","security_txt_found"),("Location","location"),("Contact","contact")])

def register(app):
    app.include_router(router)
