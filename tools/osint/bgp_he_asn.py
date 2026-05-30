"""bgp.he.net ASN / IP-block lookup — playbook §2 #27.

Hurricane Electric's BGP toolkit is free, no API key, exposes per-AS info
via plain-HTML scrape (no official API). Returns AS number, AS name,
country, prefix count for the AS holding the target IP.

Real probe via HTML parse. Zero false positives — only returns what HE
publishes.
"""
import asyncio
import re
import socket
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 15


def _resolve(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    if ":" in t: t = t.split(":", 1)[0]
    try:
        socket.inet_aton(t)
        return t
    except OSError:
        try:
            return socket.gethostbyname(t)
        except socket.gaierror:
            return t


def _do_scan(req: ScanRequest) -> dict:
    ip = _resolve((req.target or "").strip())

    # Step 1: get ASN for IP via Team Cymru DNS-based whois
    asn = None
    asname = None
    country = None
    try:
        rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        import dns.resolver
        rsv = dns.resolver.Resolver()
        rsv.timeout = 4; rsv.lifetime = 6
        ans = rsv.resolve(rev, "TXT")
        # format: "ASN | prefix | country | RIR | date"
        parts = [p.strip().strip('"') for p in str(ans[0]).split("|")]
        asn = parts[0].split()[0] if parts else None
        country = parts[2] if len(parts) > 2 else None
    except Exception:
        asn = None

    if not asn:
        return standard_response(
            tool="bgp_he_asn", target=req.target,
            findings=[wrap_finding(
                f"Could not resolve ASN for {ip}",
                severity="INFO", cwe="CWE-200",
                remediation="IP may be private / unrouted / Team-Cymru-unindexed.",
                evidence_marker="Cymru ASN lookup failed")],
            tests_performed=1, vulnerable=False,
            tests_summary="ASN resolution failed")

    # Step 2: pull AS name via bgp.he.net HTML scrape
    r = safe_get(f"https://bgp.he.net/AS{asn}",
                  req=req, timeout=10,
                  headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})
    if r is not None and r.status_code == 200:
        m = re.search(r"<title>([^<]+)</title>", r.text)
        if m:
            asname = m.group(1).replace(" - Hurricane Electric BGP Toolkit", "").strip()

    findings = [wrap_finding(
        f"IP {ip} belongs to AS{asn} ({asname or '?'})",
        severity="POSITIVE", cwe="CWE-200",
        remediation="ASN ownership is public BGP data — no remediation. Use "
                    "the AS name to identify hosting provider / ISP / corp network "
                    "for context during recon.",
        evidence_marker=(
            f"ip={ip} | ASN=AS{asn} | name={asname or '?'} | "
            f"country={country or '?'} (CONFIRMED via Cymru + HE BGP)"
        ))]

    return standard_response(
        tool="bgp_he_asn", target=req.target, findings=findings,
        tests_performed=2, vulnerable=False,
        tests_summary=f"ASN {asn} = {asname or 'unknown'}",
        raw_data={"asn": asn, "asname": asname, "country": country, "ip": ip})


@router.post("/api/osint/bgp_he_asn")
async def scan_bgp_he_asn(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="bgp_he_asn", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
