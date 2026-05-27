"""permutation_gen — VL-FORGE Recon §3 Subdomain Enumeration (real, zero-FP)."""
import asyncio, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._subdomain_helpers import resolves, bulk_check


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    SEEDS = ["www","api","admin","dev","staging","test","app","portal"]
    # Confirm a seed exists, then permute around it
    confirmed_seeds = await bulk_check([f"{s}.{h}" for s in SEEDS], concurrency=15)
    perms = []
    for s in confirmed_seeds:
        prefix = s.split(".",1)[0]
        for suf in ("dev","staging","test","prod","new","old","v2","beta","internal","ext"):
            perms.append(f"{prefix}-{suf}.{h}")
            perms.append(f"{prefix}.{suf}.{h}")
            perms.append(f"{suf}-{prefix}.{h}")
    perms = list(set(perms))[:80]
    found = await bulk_check(perms, concurrency=25)
    ctx.state["seeds_confirmed"] = confirmed_seeds
    ctx.state["permutations_tried"] = len(perms)
    ctx.state["discovered"] = found
    ctx.state["count"] = len(found)
    ctx.source("Permutation-based subdomain generation from confirmed seeds")

RULES = [

]

@router.post("/api/recon/permutation_gen")
async def recon_permutation_gen(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="permutation_gen",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Seeds Confirmed","seeds_confirmed"),("Discovered","discovered"),("Count","count")])

def register(app):
    app.include_router(router)
