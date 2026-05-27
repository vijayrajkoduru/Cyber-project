"""dns_rebinding — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at
import ipaddress

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    try:
        import dns.resolver
        ans = await asyncio.to_thread(dns.resolver.resolve, h, "A", lifetime=5)
        ttl = ans.rrset.ttl if ans.rrset else 999999
        ips = [str(r) for r in ans]
    except Exception:
        ttl, ips = 999999, []
    private = [ip for ip in ips if ipaddress.ip_address(ip).is_private] if ips else []
    ctx.state["ttl"] = ttl
    ctx.state["ips"] = ips
    ctx.state["private_ips"] = private
    ctx.state["rebind_risk"] = ttl < 60 and bool(private)
    ctx.source("A record TTL + private-IP analysis")

RULES = [
    lambda s: {"name":"DNS Rebinding Susceptibility — short TTL + private IPs","severity":"MEDIUM",
        "evidence":f"A records {s.get('ips')} include private IPs {s.get('private_ips')} with TTL={s.get('ttl')}s — attacker can rebind to internal hosts",
        "remediation":"Increase TTL to 300+ OR block private IPs from resolving for public hosts (split-horizon DNS)",
        "cwe":"CWE-350","owasp":"A10:2021"
    } if s.get("rebind_risk") else None,
]

@router.post("/api/recon/dns_rebinding")
async def recon_dns_rebinding(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="dns_rebinding",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Ttl","ttl"),("Ips","ips"),("Private Ips","private_ips")])

def register(app):
    app.include_router(router)
