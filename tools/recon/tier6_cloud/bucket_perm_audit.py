"""bucket_perm_audit — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    # Test if any known bucket allows PUT (writable) — using PROPFIND-like probe (HEAD with Authorization=anon)
    base_name = h.split(".")[0]
    writable = []
    for url in (f"http://{base_name}.s3.amazonaws.com/vulnuslab-probe.txt",
                f"https://storage.googleapis.com/{base_name}/vulnuslab-probe.txt"):
        c, h2, _ = await fetch(url, method="PUT", body=b"test", timeout=4)
        if c in (200, 204): writable.append(url)
    ctx.state["writable_endpoints"] = writable
    ctx.source("Anonymous PUT probe on candidate buckets")

RULES = [
    lambda s: {"name":"Cloud Bucket Allows Anonymous Write","severity":"CRITICAL",
        "evidence":f"Anonymous PUT succeeded: {s.get('writable_endpoints')}",
        "remediation":"Remove allUsers/anonymous WRITE permission immediately. Audit IAM policies.",
        "cwe":"CWE-284","owasp":"A01:2021"
    } if s.get("writable_endpoints") else None,
]

@router.post("/api/recon/bucket_perm_audit")
async def recon_bucket_perm_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="bucket_perm_audit",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Writable Endpoints","writable_endpoints")])

def register(app):
    app.include_router(router)
