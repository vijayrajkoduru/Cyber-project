"""dns_records — VL-FORGE Recon §2 #16: Standard records (parallel)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    types = ("A","AAAA","MX","NS","TXT","SOA","CNAME")
    results = await asyncio.gather(*[query(h, t) for t in types])
    for t, r in zip(types, results):
        ctx.state[f"{t.lower()}_records"] = r
    ctx.state["has_ns"] = bool(ctx.state.get("ns_records"))
    ctx.state["has_mx"] = bool(ctx.state.get("mx_records"))
    ctx.source("dnspython parallel resolver")

RULES = [
    lambda s: {"name":"No MX records configured","severity":"LOW",
        "evidence":f"NS={s.get('ns_records')} but no MX — email won't deliver",
        "remediation":"Add MX records if email is expected","cwe":"N/A","owasp":"N/A"
    } if s.get("has_ns") and not s.get("has_mx") else None,
]

@router.post("/api/recon/dns_records")
async def recon_dns_records(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="dns_records",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("A Records","a_records"),("AAAA Records","aaaa_records"),("MX Records","mx_records"),("NS Records","ns_records"),("TXT Records","txt_records"),("SOA Records","soa_records"),("CNAME Records","cname_records")])

def register(app):
    app.include_router(router)
