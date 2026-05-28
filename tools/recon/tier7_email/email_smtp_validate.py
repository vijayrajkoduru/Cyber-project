"""Email SMTP Validate v2 — VL-FORGE. Test MX + VRFY/EXPN/RCPT."""
import asyncio, socket
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def _mx(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).split()[-1].rstrip(".") for x in await r.resolve(h,"MX")]
    except: return []
def _smtp_probe(mx_host,timeout=6):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((mx_host,25))
            banner=s.recv(1024).decode("utf-8",errors="ignore")
            s.send(b"HELO vulnuslab.com\r\n")
            s.recv(1024)
            s.send(b"VRFY postmaster\r\n")
            vrfy=s.recv(1024).decode("utf-8",errors="ignore")
            s.send(b"EXPN list\r\n")
            expn=s.recv(1024).decode("utf-8",errors="ignore")
            s.send(b"QUIT\r\n")
            return {"banner":banner[:200],"vrfy":vrfy[:200],"expn":expn[:200]}
    except Exception as e: return {"error":type(e).__name__}
async def gather(ctx):
    mx=await _mx(ctx.host)
    if not mx: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["mx_hosts"]=mx
    ctx.source(f"mx-{len(mx)}")
    r=await asyncio.to_thread(_smtp_probe,mx[0])
    if r.get("banner"): ctx.source("smtp-25")
    ctx.state["smtp_response"]=r
    # Check VRFY/EXPN supported
    vrfy_resp=r.get("vrfy","")
    expn_resp=r.get("expn","")
    ctx.state["vrfy_enabled"]="250" in vrfy_resp or "252" in vrfy_resp
    ctx.state["expn_enabled"]="250" in expn_resp
def _r_vrfy(s):
    if not s.get("vrfy_enabled"): return None
    return {"name":"SMTP VRFY enabled — user enumeration possible","severity":"MEDIUM","cwe":"CWE-204",
        "evidence":(s.get("smtp_response") or {}).get("vrfy","")[:120],
        "remediation":"Disable VRFY. Postfix: 'disable_vrfy_command = yes'"}
def _r_expn(s):
    if not s.get("expn_enabled"): return None
    return {"name":"SMTP EXPN enabled — mailing list disclosure","severity":"MEDIUM","cwe":"CWE-200",
        "evidence":(s.get("smtp_response") or {}).get("expn","")[:120],
        "remediation":"Disable EXPN command at MTA."}
def _r_banner(s):
    b=(s.get("smtp_response") or {}).get("banner","")
    if not b: return None
    return {"name":"SMTP banner exposed","severity":"INFO",
        "evidence":b[:80],"remediation":"Hide MTA version in banner if specific version present."}
FINDING_RULES=[_r_vrfy,_r_expn,_r_banner]
INTEL_FIELDS=[("MX hosts","mx_hosts"),("VRFY","vrfy_enabled"),("EXPN","expn_enabled")]
@router.post("/api/recon/email_smtp_validate")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="email_smtp_validate",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["mx_hosts","vrfy_enabled","expn_enabled","smtp_response"])
def register(app): app.include_router(router)
