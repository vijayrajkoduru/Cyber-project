"""lb_detection — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    a = await query(h, "A")
    aaaa = await query(h, "AAAA")
    ctx.state["a_records"] = a
    ctx.state["aaaa_records"] = aaaa
    ctx.state["lb_detected"] = len(a) > 1 or len(aaaa) > 1
    ctx.source("Multi-A round-robin detection")

RULES = [
    # Intel-only: load balancers aren't vulnerabilities

]

@router.post("/api/recon/lb_detection")
async def recon_lb_detection(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="lb_detection",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("A Records","a_records"),("AAAA Records","aaaa_records"),("Lb Detected","lb_detected")])

def register(app):
    app.include_router(router)
