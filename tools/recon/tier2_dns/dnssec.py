"""dnssec — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    dnskey, ds, rrsig = await asyncio.gather(query(h,"DNSKEY"), query(h,"DS"), query(h,"RRSIG"))
    ctx.state["has_dnskey"] = bool(dnskey)
    ctx.state["has_ds"]     = bool(ds)
    ctx.state["has_rrsig"]  = bool(rrsig)
    ctx.state["dnssec_enabled"] = bool(dnskey and rrsig)
    # weak algo check (SHA-1 = algo 5 or 7)
    weak = any(" 5 " in k or " 7 " in k for k in dnskey)
    ctx.state["weak_algo"] = weak
    ctx.source("DNSKEY/DS/RRSIG lookup")

RULES = [
    lambda s: {"name":"DNSSEC not enabled","severity":"LOW",
        "evidence":"No DNSKEY/RRSIG records — domain is vulnerable to DNS spoofing/cache poisoning",
        "remediation":"Enable DNSSEC at your registrar and publish DS record to parent zone",
        "cwe":"CWE-345","owasp":"N/A"
    } if not s.get("dnssec_enabled") else None,
    lambda s: {"name":"DNSSEC uses weak SHA-1 algorithm","severity":"MEDIUM",
        "evidence":"DNSKEY uses algorithm 5/7 (SHA-1) — deprecated since 2018",
        "remediation":"Roll DNSSEC keys to algorithm 8 (RSA/SHA-256) or 13 (ECDSA P-256)",
        "cwe":"CWE-327","owasp":"N/A"
    } if s.get("dnssec_enabled") and s.get("weak_algo") else None,
]

@router.post("/api/recon/dnssec")
async def recon_dnssec(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="dnssec",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Has Dnskey","has_dnskey"),("Has Ds","has_ds"),("Has Rrsig","has_rrsig"),("Weak Algo","weak_algo")])

def register(app):
    app.include_router(router)
