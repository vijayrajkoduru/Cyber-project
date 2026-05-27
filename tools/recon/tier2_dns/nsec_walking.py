"""nsec_walking — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    nsec  = await query(h, "NSEC")
    nsec3 = await query(h, "NSEC3PARAM")
    discovered = []
    walkable = False
    if nsec:
        walkable = True
        # Walk a few hops
        cur = h
        for _ in range(5):
            r = await query(cur, "NSEC")
            if not r: break
            nxt = r[0].split()[0].rstrip(".")
            if nxt in discovered or nxt == cur: break
            discovered.append(nxt); cur = nxt
    ctx.state["nsec_records"]  = nsec
    ctx.state["nsec3_present"] = bool(nsec3)
    ctx.state["walkable"]      = walkable
    ctx.state["walked"]        = discovered
    ctx.source("NSEC/NSEC3 walk")

RULES = [
    lambda s: {"name":"DNSSEC NSEC zone-walking possible","severity":"MEDIUM",
        "evidence":f"NSEC records expose zone contents — walked {len(s.get('walked',[]))} entries: {s.get('walked')[:5]}",
        "remediation":"Switch from NSEC to NSEC3 (RFC 5155) with salt + iterations",
        "cwe":"CWE-200","owasp":"A01:2021"
    } if s.get("walkable") else None,
]

@router.post("/api/recon/nsec_walking")
async def recon_nsec_walking(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="nsec_walking",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("NSEC Records","nsec_records"),("Nsec3 Present","nsec3_present"),("Walked","walked")])

def register(app):
    app.include_router(router)
