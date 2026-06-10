"""AI Wordlist Subdomain v2 — VL-FORGE. Curated AI wordlist."""
import asyncio
from pathlib import Path
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
_PAYLOAD=Path(__file__).resolve().parent.parent.parent/"_payloads"/"recon"/"ai_subs.txt"
_FB=["api","admin","app","portal","staging","dev","beta","internal","corp","vpn","mail","cdn","graphql","gql","auth","sso","webhook","grafana","jenkins","kibana"]
async def _q(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=3;r.lifetime=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
def _load(cap=1000):
    try:
        if _PAYLOAD.exists():
            return [l.strip().lower() for l in _PAYLOAD.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")][:cap]
    except: pass
    return _FB
async def gather(ctx):
    words=_load()
    ctx.state["wordlist_size"]=len(words)
    ctx.source(f"ai-curated-{len(words)}")
    sem=asyncio.Semaphore(50)
    async def one(w):
        async with sem:
            sub=f"{w}.{ctx.host}"; ips=await _q(sub)
            return {"subdomain":sub,"ips":ips} if ips else None
    res=await asyncio.gather(*[one(w) for w in words])
    found=[r for r in res if r]
    ctx.state["subdomains_found"]=found; ctx.state["count"]=len(found)
    if found: ctx.source(f"resolved-{len(found)}")
# VL-VERIFY (zero-FP): some SaaS providers EXPOSE these subdomain names by
# design (admin.google.com = Google Workspace admin console, login.microsoft
# .com, console.aws.amazon.com, etc.). Flagging them as "high-value exposed"
# is wrong - they are public by design. We skip when the subdomain is on
# the public-by-design allowlist.
_PUBLIC_BY_DESIGN = {
    "admin.google.com",          # Google Workspace admin
    "admin.microsoft.com",       # Microsoft 365 admin
    "admin.office.com",          # Microsoft 365 admin alt
    "console.aws.amazon.com",    # AWS console
    "portal.azure.com",          # Azure portal
    "console.cloud.google.com",  # GCP console
    "login.microsoftonline.com", # Microsoft login
    "admin.shopify.com",         # Shopify
    "admin.atlassian.com",       # Atlassian admin
    "id.atlassian.com",
    "admin.slack.com",
    "admin.zoom.us",
}


def _r_high_value(s):
    found=s.get("subdomains_found") or []
    raw_high=[f for f in found if any(k in f["subdomain"].lower() for k in
              ["admin","internal","vpn","jenkins","grafana","kibana","staging","dev"])]
    # Filter out public-by-design admin subdomains
    high_value=[f for f in raw_high
                 if f["subdomain"].lower().strip(".") not in _PUBLIC_BY_DESIGN]
    suppressed=[f["subdomain"] for f in raw_high
                 if f["subdomain"].lower().strip(".") in _PUBLIC_BY_DESIGN]
    if suppressed:
        s["high_value_suppressed"] = suppressed
    if not high_value: return None
    return {"name":f"High-value subdomains exposed ({len(high_value)})","severity":"MEDIUM","cwe":"T1596.001",
        "evidence":"; ".join(h["subdomain"] for h in high_value[:5]),
        "remediation":"Internal/admin subdomains should not be publicly resolvable. IP-restrict or VPN-gate."}
def _r_count(s):
    n=s.get("count",0)
    if n==0: return None
    return {"name":f"{n} subdomains via AI wordlist","severity":"INFO","cwe":"T1596.001",
        "evidence":"Sample: "+", ".join(f["subdomain"] for f in (s.get("subdomains_found") or [])[:5])}
def _r_clean(s):
    if s.get("count",0)>0: return None
    return {"name":"No subdomains via AI wordlist","severity":"POSITIVE",
        "evidence":f"Probed {s.get('wordlist_size',0)} AI-curated terms"}
FINDING_RULES=[_r_high_value,_r_count,_r_clean]
INTEL_FIELDS=[("Wordlist size","wordlist_size"),("Subdomains","count")]
@router.post("/api/recon/ai_wordlist_subdomain")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="ai_wordlist_subdomain",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains_found","count"])
def register(app): app.include_router(router)
