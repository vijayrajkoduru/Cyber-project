"""shuffled_bruteforce — VL-FORGE Recon §3 Subdomain Enumeration (real, zero-FP)."""
import asyncio, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._subdomain_helpers import resolves, bulk_check
import random

router = APIRouter()

async def gather(ctx: ScanContext):
    EXT = ["api","api1","api2","api3","api-dev","api-test","api-staging","api-prod","api-v1","api-v2",
           "beta","alpha","gamma","preview","sandbox","demo","tmp","temp","old","new",
           "admin1","admin2","backup","backup1","backup2","store","stores","mobile","m","mobile-api",
           "edge","origin","ws","ws1","ws2","grpc","mq","queue","jobs","worker"]
    h = ctx.host
    random.shuffle(EXT)
    candidates = [f"{p}.{h}" for p in EXT]
    found = await bulk_check(candidates, concurrency=25)
    ctx.state["wordlist_size"] = len(candidates)
    ctx.state["discovered"] = found
    ctx.state["count"] = len(found)
    ctx.source("Shuffled-order DNS probe")

RULES = [

]

@router.post("/api/recon/shuffled_bruteforce")
async def recon_shuffled_bruteforce(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="shuffled_bruteforce",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered","discovered"),("Count","count")])

def register(app):
    app.include_router(router)
