"""Security.txt v2 — VL-FORGE. RFC 9116 disclosure file."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _g(u):
    try: return requests.get(u,timeout=8,verify=False,headers={"User-Agent":"VulnusLab/1.0"})
    except: return None
async def gather(ctx):
    base=web_url(ctx.host).rstrip("/")
    r1,r2=await asyncio.gather(
        asyncio.to_thread(_g,base+"/.well-known/security.txt"),
        asyncio.to_thread(_g,base+"/security.txt"))
    found=r1 if r1 and r1.status_code==200 else (r2 if r2 and r2.status_code==200 else None)
    if not found: ctx.state["found"]=False; return
    ctx.state["found"]=True
    ctx.source("security.txt")
    ctx.state["raw"]=found.text[:5000]
    import re
    contact=re.search(r"Contact:\s*([^\r\n]+)",found.text,re.I)
    expires=re.search(r"Expires:\s*([^\r\n]+)",found.text,re.I)
    encryption=re.search(r"Encryption:\s*([^\r\n]+)",found.text,re.I)
    policy=re.search(r"Policy:\s*([^\r\n]+)",found.text,re.I)
    ctx.state.update({"contact":contact.group(1).strip() if contact else None,
        "expires":expires.group(1).strip() if expires else None,
        "encryption":encryption.group(1).strip() if encryption else None,
        "policy":policy.group(1).strip() if policy else None})
def _r_missing(s):
    if s.get("found"): return None
    return {"name":"No security.txt published","severity":"LOW","cwe":"CWE-1059",
        "evidence":"Neither /.well-known/security.txt nor /security.txt found",
        "remediation":"Publish RFC 9116 security.txt at /.well-known/security.txt — helps researchers report bugs."}
def _r_present(s):
    if not s.get("found"): return None
    return {"name":"security.txt published","severity":"POSITIVE","cwe":"T1591",
        "evidence":f"Contact: {s.get('contact','?')} | Expires: {s.get('expires','?')}"}
def _r_expired(s):
    exp=s.get("expires")
    if not exp: return None
    from datetime import datetime
    try:
        dt=datetime.fromisoformat(exp.replace("Z","+00:00"))
        if dt < datetime.now(dt.tzinfo):
            return {"name":"security.txt has EXPIRED","severity":"LOW","cwe":"CWE-1059",
                "evidence":f"Expires: {exp}","remediation":"Update Expires: in security.txt."}
    except: pass
FINDING_RULES=[_r_missing,_r_expired,_r_present]
INTEL_FIELDS=[("Found","found"),("Contact","contact"),("Expires","expires"),
    ("Encryption","encryption"),("Policy","policy")]
@router.post("/api/recon/security_txt")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="security_txt",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["found","contact","expires"])
def register(app): app.include_router(router)
