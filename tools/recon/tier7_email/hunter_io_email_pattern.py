"""Hunter.io Email Pattern v2 — VL-FORGE. Discover email format + employees."""
import asyncio, requests, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def gather(ctx):
    key=os.environ.get("HUNTER_API_KEY","")
    ctx.state["api_key_configured"]=bool(key)
    if not key: return
    try:
        r=await asyncio.to_thread(requests.get,
            f"https://api.hunter.io/v2/domain-search?domain={ctx.host}&limit=50&api_key={key}",timeout=15)
        if r.status_code==200:
            d=r.json().get("data",{})
            ctx.source("hunter.io")
            ctx.state.update({"organization":d.get("organization"),
                "pattern":d.get("pattern"),"webmail":d.get("webmail"),
                "disposable":d.get("disposable"),
                "emails":[e.get("value") for e in (d.get("emails") or [])[:20]],
                "email_count":len(d.get("emails",[]))})
        elif r.status_code in (401,403): ctx.state["auth_error"]=True
        elif r.status_code==429: ctx.state["rate_limited"]=True
    except Exception: pass
def _r_pattern(s):
    p=s.get("pattern")
    if not p: return None
    return {"name":f"Email pattern: {p}@{s.get('organization','target')}","severity":"INFO","cwe":"T1589.002",
        "evidence":f"Pattern: {p} | Emails: {s.get('email_count',0)}",
        "remediation":"Predictable email format = phishing/spear-phishing target. Train staff."}
def _r_emails(s):
    n=s.get("email_count",0)
    if n==0: return None
    return {"name":f"{n} employee emails discoverable","severity":"MEDIUM","cwe":"CWE-200",
        "evidence":"Sample: "+", ".join((s.get("emails") or [])[:5]),
        "remediation":"Public email exposure increases phishing risk."}
def _r_no_key(s):
    if s.get("api_key_configured"): return None
    return {"name":"HUNTER_API_KEY not set","severity":"INFO","evidence":"Free 25/month at hunter.io"}
FINDING_RULES=[_r_emails,_r_pattern,_r_no_key]
INTEL_FIELDS=[("API key","api_key_configured"),("Pattern","pattern"),("Organization","organization"),
    ("Email count","email_count")]
@router.post("/api/recon/hunter_io_email_pattern")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="hunter_io_email_pattern",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["pattern","emails","email_count","organization"])
def register(app): app.include_router(router)
