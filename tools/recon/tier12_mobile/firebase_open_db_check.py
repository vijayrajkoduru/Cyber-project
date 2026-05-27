"""firebase_open_db_check — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    name = ctx.host.split(".")[0]
    open_dbs = []
    for db in (name, f"{name}-prod", f"{name}-dev", f"{name}-default-rtdb"):
        for region in ("",".firebaseio.com",".region1.firebasedatabase.app"):
            host = db + (".firebaseio.com" if not region else region) if not region.startswith(".region") else db + region
            url = f"https://{host}/.json"
            code, d = await get_json(url, timeout=5)
            if code == 200 and d is not None and d != {{}}:
                # Anonymously readable DB
                open_dbs.append({"url":url,"sample_keys":list(d.keys())[:5] if isinstance(d,dict) else []})
                break
    ctx.state["open_databases"] = open_dbs
    ctx.source("Firebase RTDB /.json anonymous read probe")

RULES = [
    lambda s: {"name":"Firebase Realtime Database Publicly Readable","severity":"CRITICAL",
        "evidence":f"Anonymous /.json returned data: {s.get('open_databases')}",
        "remediation":"Set Firebase rules: { .read: auth != null, .write: auth != null }. Audit Firestore rules too.",
        "cwe":"CWE-284","owasp":"A01:2021"
    } if s.get("open_databases") else None,
]

@router.post("/api/recon/firebase_open_db_check")
async def recon_firebase_open_db_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="firebase_open_db_check",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Open Databases","open_databases")])

def register(app):
    app.include_router(router)
