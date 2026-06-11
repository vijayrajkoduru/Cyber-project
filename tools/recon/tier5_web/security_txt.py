"""Security.txt v2 — VL-FORGE. RFC 9116 disclosure file.

VL-VERIFY: SPAs catch-all every path to index.html, so a naive 200 check
would falsely report "security.txt published" with empty Contact. We
require Contact: marker in the body before accepting the file as real.
"""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools._vl_core.spa_canary import detect_spa_catchall_sync, is_same_as_canary
router=APIRouter()
def _g(u):
    try: return requests.get(u,timeout=8,verify=False,headers={"User-Agent":"VulnusLab/1.0"})
    except Exception: return None
def _is_real_security_txt(body):
    """RFC 9116 requires Contact: field. Without it, body is not security.txt."""
    if not body: return False
    return "Contact:" in body[:5000] or "contact:" in body[:5000].lower()
async def gather(ctx):
    base=web_url(ctx.host).rstrip("/")
    # VL-VERIFY: probe SPA canary once so we can drop catch-all responses
    spa = await asyncio.to_thread(detect_spa_catchall_sync, base)
    ctx.state["spa_catchall"] = spa.get("is_spa", False)
    r1,r2=await asyncio.gather(
        asyncio.to_thread(_g,base+"/.well-known/security.txt"),
        asyncio.to_thread(_g,base+"/security.txt"))
    def _ok(r):
        if not r or r.status_code != 200: return False
        body = r.text or ""
        # SPA catch-all returns same body for every path — reject
        if spa.get("is_spa") and is_same_as_canary(body, spa.get("canary_body","")):
            return False
        # RFC 9116 requires Contact field. Without it, we caught a 200 from
        # the wrong file (custom 404, SPA shell, etc.) — reject.
        return _is_real_security_txt(body)
    found = r1 if _ok(r1) else (r2 if _ok(r2) else None)
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
    except Exception: pass
FINDING_RULES=[_r_missing,_r_expired,_r_present]
INTEL_FIELDS=[("Found","found"),("Contact","contact"),("Expires","expires"),
    ("Encryption","encryption"),("Policy","policy")]
@router.post("/api/recon/security_txt")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="security_txt",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["found","contact","expires"])
def register(app): app.include_router(router)
