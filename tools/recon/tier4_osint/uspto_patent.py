"""uspto_patent — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    name = ctx.host.split(".")[0]
    code, d = await get_json(f"https://search.patentsview.org/api/v1/patent/?q={{\"assignees.assignee_organization\":\"{name}\"}}&f=[\"patent_id\",\"patent_title\"]&o={{\"size\":10}}")
    patents = (d or {{}}).get("patents",[]) if isinstance(d, dict) else []
    ctx.state["patents"] = patents[:10]
    ctx.state["count"] = len(patents)
    ctx.source("PatentsView API (USPTO)")

RULES = [

]

@router.post("/api/recon/uspto_patent")
async def recon_uspto_patent(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="uspto_patent",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Patents","patents"),("Count","count")])

def register(app):
    app.include_router(router)
