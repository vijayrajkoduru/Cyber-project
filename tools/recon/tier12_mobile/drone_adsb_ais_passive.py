"""drone_adsb_ais_passive — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    ctx.state["scannable"] = False
    ctx.state["note"] = "ADS-B/AIS require local RTL-SDR hardware. Cloud feeds (adsbexchange, flightaware) accessible but not target-scoped."
    ctx.source("ADS-B/AIS — local SDR required")

RULES = [

]

@router.post("/api/recon/drone_adsb_ais_passive")
async def recon_drone_adsb_ais_passive(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="drone_adsb_ais_passive",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Scannable","scannable"),("Note","note")])

def register(app):
    app.include_router(router)
