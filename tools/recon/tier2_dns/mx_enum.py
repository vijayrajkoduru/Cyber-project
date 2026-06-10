"""MX Enum v2 — VL-FORGE. MX records + reverse DNS + provider fingerprint."""
import asyncio
import dns.asyncresolver, dns.reversename
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
_PROVIDERS={"google.com":"Google Workspace","googlemail.com":"Google Workspace",
    "outlook.com":"Microsoft 365","mimecast":"Mimecast","proofpoint":"Proofpoint",
    "barracudanetworks":"Barracuda","mxlogic":"McAfee SaaS","fastmail":"Fastmail",
    "zoho.com":"Zoho Mail","amazonaws":"AWS SES","sendgrid":"SendGrid",
    "mailgun":"Mailgun","postmark":"Postmark","mandrill":"Mandrill","sparkpost":"SparkPost"}
async def _q(h,rt):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        return [str(x).rstrip(".") for x in await r.resolve(h,rt)]
    except: return []
async def _ptr(ip):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=3;r.lifetime=5
        return [str(x).rstrip(".") for x in await r.resolve(dns.reversename.from_address(ip),"PTR")]
    except: return []
async def gather(ctx):
    mx=await _q(ctx.host,"MX")
    if not mx: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["mx_records"]=mx
    ctx.source(f"mx-{len(mx)}")
    # Resolve MX hosts
    mx_hosts=[m.split()[-1] if " " in m else m for m in mx]
    mx_ips=await asyncio.gather(*[_q(h,"A") for h in mx_hosts[:5]])
    all_ips=[ip for sub in mx_ips for ip in sub]
    if all_ips: ctx.source(f"mx-ips-{len(all_ips)}")
    # PTR for each IP
    ptrs=await asyncio.gather(*[_ptr(ip) for ip in all_ips[:5]])
    ptr_data={ip:p for ip,p in zip(all_ips[:5],ptrs) if p}
    # Provider fingerprint
    blob=" ".join(mx_hosts + [p for sub in ptrs for p in sub]).lower()
    provider=next((v for k,v in _PROVIDERS.items() if k in blob),None)
    if provider: ctx.source(f"provider-{provider}")
    ctx.state.update({"mx_hosts":mx_hosts,"mx_ips":all_ips,"ptr_data":ptr_data,
        "provider":provider,"single_mx":len(mx)==1})
def _r_provider(s):
    if not s.get("provider"): return None
    return {"name":f"Mail provider: {s['provider']}","severity":"INFO","cwe":"T1592",
        "evidence":f"MX fingerprint match"}
def _r_single_mx(s):
    """VL-VERIFY (zero-FP): cloud mail providers (Google Workspace,
    Microsoft 365, etc.) expose a single MX hostname that internally
    load-balances across multiple backend hosts. Flagging 'single MX (no
    fallback)' on those is FP - the HA is hidden behind the one hostname.
    Only flag when the provider is unknown."""
    if not s.get("single_mx"): return None
    if not s.get("mx_records"): return None
    if s.get("provider"): return None  # cloud mail = HA behind one hostname
    return {"name":"Single MX record (no fallback)","severity":"LOW",
        "evidence":f"MX: {s['mx_records']}",
        "remediation":"Add backup MX with higher priority for redundancy."}
def _r_no_mx(s):
    if s.get("reachable"): return None
    return {"name":"No MX records","severity":"LOW",
        "evidence":"Domain doesn't receive email — verify intentional"}
def _r_mx_count(s):
    mx=s.get("mx_records") or []
    if not mx: return None
    return {"name":f"{len(mx)} MX record(s)","severity":"INFO",
        "evidence":f"Hosts: {', '.join(s.get('mx_hosts') or [])[:120]}"}
FINDING_RULES=[_r_no_mx,_r_single_mx,_r_provider,_r_mx_count]
INTEL_FIELDS=[("MX records","mx_records"),("MX hosts","mx_hosts"),
    ("MX IPs","mx_ips"),("Provider","provider"),("PTR data","ptr_data")]
@router.post("/api/recon/mx_enum")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="mx_enum",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["mx_records","mx_hosts","provider"])
def register(app): app.include_router(router)
