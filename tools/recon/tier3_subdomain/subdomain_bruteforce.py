"""subdomain_bruteforce — VL-FORGE Recon §3 Subdomain Enumeration (real, zero-FP)."""
import asyncio, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._subdomain_helpers import resolves, bulk_check


router = APIRouter()

async def gather(ctx: ScanContext):
    COMMON = ["www","mail","ftp","admin","api","dev","staging","test","blog","shop",
              "app","portal","secure","login","auth","cdn","static","assets","img","cms",
              "git","gitlab","jenkins","ci","build","deploy","monitor","status","health","metrics",
              "vpn","remote","ssh","db","mysql","postgres","mongo","redis","cache","queue",
              "internal","intranet","wiki","docs","support","help","kb","forum","community","old"]
    h = ctx.host
    candidates = [f"{p}.{h}" for p in COMMON]
    found = await bulk_check(candidates, concurrency=25)
    ctx.state["wordlist_size"] = len(candidates)
    ctx.state["discovered"] = found
    ctx.state["count"] = len(found)
    ctx.source("DNS bruteforce — top 50 common subdomains")

RULES = [

]

@router.post("/api/recon/subdomain_bruteforce")
async def recon_subdomain_bruteforce(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="subdomain_bruteforce",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Wordlist Size","wordlist_size"),("Discovered","discovered"),("Count","count")])

def register(app):
    app.include_router(router)
