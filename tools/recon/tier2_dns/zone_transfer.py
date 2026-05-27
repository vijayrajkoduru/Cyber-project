"""zone_transfer — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at
import dns.zone, dns.query

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    ns_list = await resolve_ns(h)
    ctx.state["ns_list"] = ns_list
    leaked_from = []
    sample = []
    for ns in ns_list:
        try:
            zone = await asyncio.to_thread(lambda: dns.zone.from_xfr(dns.query.xfr(ns, h, lifetime=8)))
            records = list(zone.nodes.keys())
            if records:
                leaked_from.append(ns)
                sample = [str(r) for r in records[:25]]
                break
        except Exception:
            continue
    ctx.state["axfr_leaked"] = bool(leaked_from)
    ctx.state["leaked_from_ns"] = leaked_from
    ctx.state["leaked_records"] = sample
    ctx.source("DNS AXFR against each authoritative NS")

RULES = [
    lambda s: {"name":"DNS Zone Transfer (AXFR) Allowed","severity":"HIGH",
        "evidence":f"AXFR succeeded against {s.get('leaked_from_ns')} — leaked {len(s.get('leaked_records',[]))} records (sample: {s.get('leaked_records',[])[:5]})",
        "remediation":"Restrict AXFR to authorized secondaries: 'allow-transfer { authorized-ip; };' in BIND or equivalent",
        "cwe":"CWE-200","owasp":"A01:2021"
    } if s.get("axfr_leaked") else None,
]

@router.post("/api/recon/zone_transfer")
async def recon_zone_transfer(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="zone_transfer",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("NS List","ns_list"),("Axfr Leaked","axfr_leaked"),("Leaked From NS","leaked_from_ns"),("Leaked Records","leaked_records")])

def register(app):
    app.include_router(router)
