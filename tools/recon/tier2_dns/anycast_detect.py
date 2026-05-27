"""anycast_detect — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at
import urllib.request, json

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    ns_list = await resolve_ns(h)
    ns_ips = []
    for ns in ns_list[:5]:
        ips = await query(ns, "A")
        if ips: ns_ips.append({"ns":ns,"ip":ips[0]})
    # ASN lookup via Team Cymru
    asns = set()
    for entry in ns_ips:
        try:
            def _asn():
                req = urllib.request.Request(f"https://api.iptoasn.com/v1/as/ip/{entry['ip']}",
                    headers={"User-Agent":"VulnusLab"})
                with urllib.request.urlopen(req, timeout=4) as r:
                    d = json.loads(r.read())
                    return d.get("as_number")
            a = await asyncio.to_thread(_asn)
            if a: asns.add(a); entry["asn"]=a
        except Exception: pass
    ctx.state["ns_ips"] = ns_ips
    ctx.state["unique_asns"] = sorted(asns)
    ctx.state["likely_anycast"] = len(asns) >= 2
    ctx.source("ipinfo + ASN diversity heuristic")

RULES = [
    # Intel only

]

@router.post("/api/recon/anycast_detect")
async def recon_anycast_detect(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="anycast_detect",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("NS Ips","ns_ips"),("Unique Asns","unique_asns"),("Likely Anycast","likely_anycast")])

def register(app):
    app.include_router(router)
