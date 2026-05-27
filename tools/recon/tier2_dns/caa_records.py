"""caa_records — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    caa = await query(h, "CAA")
    ctx.state["caa_records"] = caa
    ctx.state["has_caa"] = bool(caa)
    ctx.source("CAA RR via dnspython")

RULES = [
    lambda s: {"name":"No CAA records — any CA can issue certificates","severity":"LOW",
        "evidence":"No CAA records found — any Certificate Authority can issue a cert for this domain",
        "remediation":"Publish CAA records to restrict cert issuance to your chosen CAs (e.g. 'letsencrypt.org')",
        "cwe":"CWE-295","owasp":"N/A"
    } if not s.get("has_caa") else None,
]

@router.post("/api/recon/caa_records")
async def recon_caa_records(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="caa_records",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("CAA Records","caa_records")])

def register(app):
    app.include_router(router)
