"""cache_snooping — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    ns_list = await resolve_ns(h)
    if not ns_list:
        ctx.state["snoopable"] = False
        ctx.source("cache snoop probe"); return
    # Resolve first NS to IP
    try:
        ns_ip = (await query(ns_list[0], "A") or [""])[0]
    except Exception:
        ns_ip = ""
    ctx.state["ns_probed"] = ns_list[0]
    if not ns_ip:
        ctx.state["snoopable"] = False
        ctx.source("cache snoop probe"); return
    # Try non-recursive query for a popular cached domain
    res = await query_at(ns_ip, "google.com", "A", recurse=False)
    ctx.state["snoopable"] = bool(res)
    ctx.state["leaked_lookup"] = "google.com" if res else ""
    ctx.source("non-recursive DNS query")

RULES = [
    lambda s: {"name":"DNS Cache Snooping Possible","severity":"MEDIUM",
        "evidence":f"Non-recursive query to NS {s.get('ns_probed')} returned cached answer for google.com — cache is enumerable",
        "remediation":"Disable recursion on authoritative-only nameservers OR restrict cache queries to internal clients",
        "cwe":"CWE-200","owasp":"A01:2021"
    } if s.get("snoopable") else None,
]

@router.post("/api/recon/cache_snooping")
async def recon_cache_snooping(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="cache_snooping",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("NS Probed","ns_probed"),("Leaked Lookup","leaked_lookup")])

def register(app):
    app.include_router(router)
