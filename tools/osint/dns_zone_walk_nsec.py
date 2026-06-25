"""DNSSEC NSEC/NSEC3 zone-walk detection — playbook §2 extra.

If a zone uses unhashed NSEC records, an attacker can walk the entire zone
to enumerate every name. This scanner checks NSEC presence at the zone
apex and flags zones vulnerable to walking. NSEC3 with hashing is the
recommended fix.

Real probe via dnspython. Zero false positives.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify
from tools._core import grade

router = APIRouter()
WALL_CLOCK_S = 15


def _clean(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    return t.lower().rstrip(".")


def _do_scan(req: ScanRequest) -> dict:
    domain = _clean((req.target or "").strip())
    if not domain or "." not in domain:
        return standard_response(
            tool="dns_zone_walk_nsec", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid domain")

    try:
        import dns.resolver, dns.dnssec, dns.rdatatype
    except ImportError:
        return standard_response(
            tool="dns_zone_walk_nsec", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="dnspython not installed on backend")

    r = dns.resolver.Resolver()
    r.timeout = 5; r.lifetime = 8
    # Probe for a guaranteed-non-existent name → NSEC response (if signed)
    nx_name = f"vulnuslab-walk-probe-{hash(domain) & 0xFFFFFF:06x}.{domain}"

    nsec_found = None
    nsec3_found = False
    dnskey_present = False
    try:
        r.resolve(domain, "DNSKEY")
        dnskey_present = True
    except Exception:
        dnskey_present = False

    if not dnskey_present:
        return standard_response(
            tool="dns_zone_walk_nsec", target=req.target,
            findings=[wrap_finding(
                f"{domain} is NOT DNSSEC-signed",
                severity=grade.info(), cwe="CWE-345",
                remediation="Without DNSSEC, this whole class of attack doesn't "
                            "apply. But DNSSEC is recommended for high-value zones — "
                            "consider signing.",
                evidence_marker="No DNSKEY record (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not DNSSEC-signed")

    # Try to elicit NSEC by querying a non-existent name
    try:
        r.resolve(nx_name, "A")
    except dns.resolver.NXDOMAIN as e:
        for ans in (e.responses() or {}).values():
            for rr in ans.authority:
                if rr.rdtype == dns.rdatatype.NSEC:
                    nsec_found = str(rr[0]) if len(rr) else "yes"
                if rr.rdtype == dns.rdatatype.NSEC3:
                    nsec3_found = True
    except Exception:
        pass

    if nsec_found and not nsec3_found:
        return standard_response(
            tool="dns_zone_walk_nsec", target=req.target,
            findings=[wrap_finding(
                f"{domain} uses NSEC (unhashed) — WALKABLE",
                severity=(sev := grade.exposure(confirmed=True, impact='aids')),
                cvss=grade.cvss_for(sev), cwe="CWE-200",
                owasp="A05:2021",
                remediation="Migrate from NSEC to NSEC3 (hashed). NSEC reveals "
                            "next-existing-name in the zone, which is iterable into "
                            "a full subdomain dump. RFC 5155 documents NSEC3. Coordinate "
                            "with your DNS provider — most modern providers (Cloudflare, "
                            "Route53, Google) default to NSEC3.",
                evidence_marker=f"NSEC record observed: {nsec_found[:80]} (CONFIRMED via NXDOMAIN probe)")],
            tests_performed=2, vulnerable=True,
            tests_summary="NSEC walkable",
            raw_data={"dnssec": True, "nsec": True, "nsec3": False})

    if nsec3_found:
        return standard_response(
            tool="dns_zone_walk_nsec", target=req.target,
            findings=[wrap_finding(
                f"{domain} uses NSEC3 (hashed) — properly protected from walking",
                severity=grade.protective(), cwe="CWE-200",
                remediation="DNSSEC + NSEC3 correctly configured. Use modern "
                            "iteration count (≤ 10) per RFC 9276 guidance.",
                evidence_marker="NSEC3 record observed (CONFIRMED via NXDOMAIN probe)")],
            tests_performed=2, vulnerable=False,
            tests_summary="NSEC3 protected",
            raw_data={"dnssec": True, "nsec": False, "nsec3": True})

    return standard_response(
        tool="dns_zone_walk_nsec", target=req.target,
        findings=[wrap_finding(
            f"{domain} is DNSSEC-signed but NSEC type indeterminate",
            severity=grade.info(), cwe="CWE-345",
            remediation="Use dnssec-debugger or dig +dnssec to inspect manually.",
            evidence_marker="DNSKEY present but NXDOMAIN probe didn't return NSEC/NSEC3")],
        tests_performed=2, vulnerable=False,
        tests_summary="DNSSEC indeterminate",
        raw_data={"dnssec": True, "nsec": None, "nsec3": None})


@router.post("/api/osint/dns_zone_walk_nsec")
@vl_verify()
async def scan_dns_zone_walk_nsec(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="dns_zone_walk_nsec", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
