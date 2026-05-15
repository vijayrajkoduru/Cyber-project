"""DNS typo-squat enumeration — homograph + omission + transposition + TLD swap, DNS-resolved in parallel."""
import asyncio
import dns.asyncresolver
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host

router = APIRouter()


HOMOGRAPHS = {"a":["4","@"],"b":["8"],"c":["k"],"e":["3"],"g":["q","9"],
              "i":["1","l"],"l":["1","i"],"o":["0"],"s":["5","z"],"t":["7"],"z":["s"]}
COMMON_TLDS = ["com","net","org","co","io","info","biz","us","uk","app","site","online","tech"]


def _generate_variants(domain):
    parts = domain.split(".", 1)
    if len(parts) != 2:
        return []
    name, tld = parts
    v = set()
    for i in range(len(name)):
        if len(name) > 3: v.add(name[:i] + name[i+1:] + "." + tld)
    for i in range(len(name)):
        v.add(name[:i+1] + name[i] + name[i+1:] + "." + tld)
    for i in range(len(name) - 1):
        v.add(name[:i] + name[i+1] + name[i] + name[i+2:] + "." + tld)
    for i, c in enumerate(name):
        for h in HOMOGRAPHS.get(c, []):
            v.add(name[:i] + h + name[i+1:] + "." + tld)
    for i in range(1, len(name)):
        v.add(name[:i] + "-" + name[i:] + "." + tld)
    for t in COMMON_TLDS:
        if t != tld:
            v.add(name + "." + t)
    v.discard(domain)
    return sorted(v)[:120]


async def _resolves(domain):
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2; resolver.lifetime = 2
        ans = await resolver.resolve(domain, "A")
        return str(ans[0])
    except Exception:
        return None


@router.post("/api/osint/dnstwist")
async def osint_dnstwist(req: ScanRequest, _=Depends(verify_scan_quota)):
    domain = recon_host(req.target).lower()
    variants = _generate_variants(domain)
    if not variants:
        return {"ok": False, "skipped_reason": f"Could not parse domain: {domain}"}
    results = await asyncio.gather(*[_resolves(v) for v in variants])
    active = [{"domain": v, "ip": ip} for v, ip in zip(variants, results) if ip is not None]
    return {"ok": True, "target": domain,
            "variants_generated": len(variants),
            "active_typosquats": active, "total_active": len(active),
            "engine": "pure-Python (omission + repetition + transposition + homograph + TLD-swap, parallel DNS)"}


def register(app):
    app.include_router(router)
