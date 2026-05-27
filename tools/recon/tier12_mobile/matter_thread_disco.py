"""matter_thread_disco — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    # Matter/Thread are LAN-only mesh networks — remote scan not meaningful.
    ctx.state["scannable"] = False
    ctx.state["note"] = "Matter (5540/UDP) and Thread/802.15.4 are LAN-only mesh; remote enumeration not feasible. Run on-LAN tools (killerbee, ZBOSS)."
    ctx.source("Matter/Thread — LAN-only (no remote probe)")

RULES = [

]

@router.post("/api/recon/matter_thread_disco")
async def recon_matter_thread_disco(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="matter_thread_disco",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Scannable","scannable"),("Note","note")])

def register(app):
    app.include_router(router)
