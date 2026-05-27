"""reverse_dns — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at
import dns.reversename, dns.resolver

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    a = await query(h, "A")
    pairs = []
    mismatches = []
    for ip in a:
        try:
            rev = dns.reversename.from_address(ip)
            ptr = await asyncio.to_thread(dns.resolver.resolve, rev, "PTR", lifetime=5)
            ptr_name = str(ptr[0]).rstrip(".")
            pairs.append({"ip": ip, "ptr": ptr_name})
            if h.lower() not in ptr_name.lower():
                mismatches.append({"ip": ip, "ptr": ptr_name, "expected": h})
        except Exception:
            pairs.append({"ip": ip, "ptr": "(no PTR)"})
    ctx.state["pairs"] = pairs
    ctx.state["mismatches"] = mismatches
    ctx.source("PTR lookup via in-addr.arpa")

RULES = [
    lambda s: {"name":"Forward-Reverse DNS Mismatch","severity":"LOW",
        "evidence":f"PTR records don't match forward record: {s.get('mismatches')[:3]}",
        "remediation":"Coordinate with your hosting provider/ISP to align PTR records with A records (improves email deliverability + SSH/banner trust)",
        "cwe":"N/A","owasp":"N/A"
    } if s.get("mismatches") else None,
]

@router.post("/api/recon/reverse_dns")
async def recon_reverse_dns(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="reverse_dns",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Pairs","pairs"),("Mismatches","mismatches")])

def register(app):
    app.include_router(router)
