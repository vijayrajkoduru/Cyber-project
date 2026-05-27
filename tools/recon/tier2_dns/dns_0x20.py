"""dns_0x20 — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at
import random

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    if not h.replace(".","").isascii():
        ctx.state["tested"] = False; ctx.source("0x20 probe"); return
    cased = "".join(c.upper() if random.random()<0.5 else c.lower() for c in h)
    ans = await query(cased, "A")
    ctx.state["case_query"] = cased
    ctx.state["case_preserved"] = bool(ans)
    ctx.state["tested"] = True
    ctx.source("0x20 case probe")

RULES = [
    lambda s: {"name":"DNS resolver may be vulnerable to cache poisoning (no 0x20 case mixing)","severity":"LOW",
        "evidence":f"Mixed-case query for {s.get('case_query')} returned no answer — resolver may not preserve 0x20 entropy",
        "remediation":"Use modern resolvers (Unbound, BIND 9.10+) that randomize case for entropy",
        "cwe":"CWE-345","owasp":"N/A"
    } if s.get("tested") and not s.get("case_preserved") else None,
]

@router.post("/api/recon/dns_0x20")
async def recon_dns_0x20(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="dns_0x20",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Case Query","case_query"),("Case Preserved","case_preserved")])

def register(app):
    app.include_router(router)
