"""recon_zone_transfer — test DNS AXFR (zone transfer) against nameservers."""
import dns.resolver, dns.zone, dns.query, dns.exception, dns.rdatatype
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host

router = APIRouter()


async def recon_zone_transfer_impl(req: ScanRequest, _=Depends(verify_scan_quota)):
    domain = recon_host(req.target)
    findings, transfers, ns_attempted = [], [], []
    try:
        ns_records = dns.resolver.resolve(domain, 'NS', lifetime=8)
        nameservers = [str(r.target).rstrip('.') for r in ns_records]
    except Exception as e:
        return {"ok": True, "vulnerable": False, "ns_attempted": [],
                "transfers": [], "skipped_reason": f"Could not resolve NS: {e}"}
    for ns in nameservers[:8]:
        ns_attempted.append(ns)
        try:
            xfr = dns.query.xfr(ns, domain, timeout=8, lifetime=15)
            zone = dns.zone.from_xfr(xfr)
            records = []
            for name, node in zone.nodes.items():
                for rds in node.rdatasets:
                    for r in rds:
                        records.append({"name": str(name),
                                        "type": dns.rdatatype.to_text(rds.rdtype),
                                        "value": str(r)})
            transfers.append({"nameserver": ns, "records_found": len(records),
                              "sample_records": records[:30]})
            findings.append({"title": f"DNS Zone Transfer (AXFR) allowed from {ns}",
                "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-200", "owasp": "A05:2021",
                "evidence": f"Transferred {len(records)} records from {ns}",
                "remediation": "Disable AXFR from public on authoritative NS."})
        except Exception:
            continue
    return {"ok": True, "vulnerable": len(findings) > 0, "findings": findings,
            "ns_attempted": ns_attempted, "transfers": transfers,
            "total_transfers": len(transfers),
            "engine": "pure-Python AXFR probe across all NS records"}



# VLERR-WRAP-V1
@router.post("/api/recon/zone_transfer")
async def recon_zone_transfer(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await recon_zone_transfer_impl(req, _)
    except Exception as _e:
        return {"ok": False,
                 "skipped_reason": f"zone_transfer scanner failed: {type(_e).__name__}: {str(_e)[:200]}",
                 "error": f"{type(_e).__name__}: {str(_e)[:300]}"}

def register(app):
    app.include_router(router)
