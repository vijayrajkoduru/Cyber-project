"""azure_blob_enum — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
from tools.recon._cloud_helpers import bucket_candidates

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    found = []
    for name in bucket_candidates(h):
        url = f"https://{name}.blob.core.windows.net/?comp=list"
        c, _, b = await fetch(url, timeout=4)
        if c in (200,400,403) and (b"AccountNotFound" not in b) and (b"BlobNotFound" in b or b"<EnumerationResults" in b or b"AuthenticationFailed" in b):
            found.append({"account":name,"status":c,"listable":c==200 and b"<EnumerationResults" in b})
    ctx.state["discovered_accounts"] = found
    ctx.source("Azure Blob storage account permutation")

RULES = [
    lambda s: {"name":"Public Azure Blob Container Lists Contents","severity":"HIGH",
        "evidence":f"Listable: {[a for a in s.get('discovered_accounts',[]) if a.get('listable')]}",
        "remediation":"Set container Public Access Level to 'Private'. Audit via Azure CLI: az storage container show-permission",
        "cwe":"CWE-284","owasp":"A01:2021"
    } if any(a.get('listable') for a in s.get("discovered_accounts",[])) else None,
]

@router.post("/api/recon/azure_blob_enum")
async def recon_azure_blob_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="azure_blob_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered Accounts","discovered_accounts")])

def register(app):
    app.include_router(router)
