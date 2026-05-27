"""wildcard_detection — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at
import secrets

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    r1 = secrets.token_hex(6) + "." + h
    r2 = secrets.token_hex(6) + "." + h
    a1 = await query(r1, "A")
    a2 = await query(r2, "A")
    wildcard = bool(a1) and bool(a2) and set(a1) == set(a2)
    ctx.state["probe_1"] = {"host": r1, "answer": a1}
    ctx.state["probe_2"] = {"host": r2, "answer": a2}
    ctx.state["wildcard"] = wildcard
    ctx.state["wildcard_ips"] = a1 if wildcard else []
    ctx.source("random-prefix DNS probe (2x)")

RULES = [
    # Intel only — wildcards aren't vulnerabilities, but they break subdomain bruteforce

]

@router.post("/api/recon/wildcard_detection")
async def recon_wildcard_detection(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="wildcard_detection",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Probe 1","probe_1"),("Probe 2","probe_2"),("Wildcard","wildcard"),("Wildcard Ips","wildcard_ips")])

def register(app):
    app.include_router(router)
