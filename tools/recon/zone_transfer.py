"""DNS Zone Transfer v2 — VL-FORGE pattern.

Route: /api/recon/zone_transfer

Sources (parallel):
  1. NS record retrieval (which nameservers to test)
  2. AXFR (full zone transfer) attempt per NS
  3. Record extraction + sample dump if successful
"""
import asyncio

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner, dns_resolve
from tools._payloads.zone_transfer_findings import ZONE_TRANSFER_FINDING_RULES

router = APIRouter()


def _attempt_axfr(domain, ns):
    """Try AXFR against one NS. Returns dict with records on success, None on failure."""
    try:
        xfr = dns.query.xfr(ns, domain, timeout=8, lifetime=15)
        zone = dns.zone.from_xfr(xfr)
        records = []
        for name, node in zone.nodes.items():
            for rds in node.rdatasets:
                for r in rds:
                    records.append({
                        "name": str(name),
                        "type": dns.rdatatype.to_text(rds.rdtype),
                        "value": str(r),
                    })
        return {"ns": ns, "records": records, "record_count": len(records)}
    except Exception:
        return None


async def gather(ctx: ScanContext):
    domain = ctx.host

    ns_records = await dns_resolve(domain, "NS")
    if not ns_records:
        return
    nameservers = [str(ns).rstrip(".") for ns in ns_records][:8]
    ctx.state["nameservers"] = nameservers
    ctx.state["nameservers_tested"] = len(nameservers)
    ctx.source("ns-discovery")

    # Try AXFR against each NS in parallel
    results = await asyncio.gather(*[
        asyncio.to_thread(_attempt_axfr, domain, ns) for ns in nameservers
    ])

    transfers = []
    for r in results:
        if r and r.get("record_count", 0) > 0:
            transfers.append({
                "ns": r["ns"],
                "record_count": r["record_count"],
                "sample_records": r["records"][:20],
            })
    ctx.state["transfers"] = transfers
    if transfers:
        ctx.source(f"axfr-success-{len(transfers)}")
    else:
        ctx.source(f"axfr-test-{len(nameservers)}-rejected")

    # Backwards-compat
    ctx.state["vulnerable"] = len(transfers) > 0
    ctx.state["ns_attempted"] = nameservers


INTEL_FIELDS = [
    ("Nameservers tested",  "nameservers_tested"),
    ("Nameservers",          "nameservers_display"),
    ("Successful AXFR",     "transfers_display"),
]


@router.post("/api/recon/zone_transfer")
async def recon_zone_transfer(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        ns = ctx.state.get("nameservers") or []
        if ns: ctx.state["nameservers_display"] = ", ".join(ns)
        t = ctx.state.get("transfers") or []
        if t:
            ctx.state["transfers_display"] = "; ".join(
                f"{x['ns']} ({x['record_count']} records)" for x in t[:3])

    return await run_scanner(
        host=host, tool="zone_transfer",
        gather_func=gather_with_display,
        finding_rules=ZONE_TRANSFER_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["vulnerable", "transfers", "ns_attempted"],
    )


def register(app):
    app.include_router(router)
