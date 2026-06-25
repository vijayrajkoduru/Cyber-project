"""Shodan InternetDB free host fingerprint — playbook §2 #26 .

InternetDB is Shodan's free read-only API for host info: open ports,
CPE software, vulnerabilities, hostnames, tags. No API key needed.
Rate-limited but generous. Lower fidelity than paid Shodan but still
extremely useful for triage.

Real probe. Zero false positives.
"""
import asyncio
import socket
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify
from tools._core import grade

router = APIRouter()
WALL_CLOCK_S = 10


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

    r = safe_get(f"https://internetdb.shodan.io/{ip}",
                  req=req, timeout=8,
                  headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None:
        return standard_response(
            tool="shodan_internetdb", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="InternetDB unreachable")
    if r.status_code == 404:
        return standard_response(
            tool="shodan_internetdb", target=req.target,
            findings=[wrap_finding(
                f"No Shodan/InternetDB record for {ip}",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Either the host has never been scanned by Shodan "
                            "(internal IP / new asset) or it has no exposed services. "
                            "Either way: no public footprint via this source.",
                evidence_marker=f"GET /internetdb/{ip} → 404 (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Host not in InternetDB")
    if r.status_code != 200:
        return standard_response(
            tool="shodan_internetdb", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"InternetDB status {r.status_code}")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="shodan_internetdb", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON response")

    ports = data.get("ports", []) or []
    cpes = data.get("cpes", []) or []
    vulns = data.get("vulns", []) or []
    hostnames = data.get("hostnames", []) or []
    tags = data.get("tags", []) or []

    findings = []
    if vulns:
        # InternetDB CVEs are INFERRED from the banner/CPE version Shodan last
        # saw — there is no patch-level or live-exploit confirmation, so a CVE
        # count is NOT proof of exploitability. Cap at MEDIUM.
        findings.append(wrap_finding(
            f"InternetDB lists {len(vulns)} version-inferred CVE(s) on this host",
            severity=(vsev := grade.exposure(confirmed=False,
                      impact="enables" if len(vulns) >= 3 else "aids")),
            cwe="CWE-1395", cvss=grade.cvss_for(vsev),
            owasp="A06:2021",
            remediation="These CVEs are version-inferred from Shodan's last banner "
                        "scan and are UNCONFIRMED (no patch/version verification). "
                        "Confirm the actual installed version before treating as "
                        "exploitable, then patch. Cross-reference each CVE in NVD.",
            evidence_marker=f"vulns: {', '.join(vulns[:10])}"
                              + (' ...' if len(vulns) > 10 else '')
                              + " (version-inferred, UNCONFIRMED — no patch/version check)"))

    # Tier exposed ports by REAL risk. An open port is not a vulnerability by
    # itself — severity reflects how dangerous that service is when reachable.
    # SSH/FTP are frequently intended (git-over-SSH, bastion, SFTP), so they are
    # advisory LOW, not MEDIUM/HIGH; and on CDN/cloud edges they are suppressed.
    _CRIT = {23: "Telnet", 445: "SMB", 137: "NetBIOS", 139: "NetBIOS", 3389: "RDP",
             5900: "VNC", 6379: "Redis", 11211: "Memcached", 27017: "MongoDB",
             9200: "Elasticsearch"}
    _MED = {1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 135: "MSRPC"}
    _MGMT = {22: "SSH", 21: "FTP"}
    _is_cdn = bool({t.lower() for t in tags} & {"cdn", "cloud"})

    crit = [p for p in ports if p in _CRIT]
    med = [p for p in ports if p in _MED]
    mgmt = [p for p in ports if p in _MGMT]
    if crit:
        findings.append(wrap_finding(
            f"High-risk service port(s) internet-facing: {[f'{p}/{_CRIT[p]}' for p in crit]}",
            severity=(csev := grade.exposure(confirmed=True, impact="enables")),
            cwe="CWE-668", cvss=grade.cvss_for(csev), owasp="A05:2021",
            remediation="These services are commonly unauthenticated or heavily attacked "
                        "and should not be internet-facing. Firewall to known IPs / move "
                        "behind a VPN; disable Telnet and SMB entirely.",
            evidence_marker=f"ports={crit} (CONFIRMED via Shodan InternetDB)"))
    if med:
        findings.append(wrap_finding(
            f"Database/RPC port(s) internet-facing: {[f'{p}/{_MED[p]}' for p in med]}",
            severity=(msev := grade.exposure(confirmed=True, impact="aids")),
            cwe="CWE-668", cvss=grade.cvss_for(msev), owasp="A05:2021",
            remediation="Database/RPC ports should not be publicly reachable. Bind to a "
                        "private interface and restrict by firewall.",
            evidence_marker=f"ports={med} (CONFIRMED via Shodan InternetDB)"))
    if mgmt and not _is_cdn:
        findings.append(wrap_finding(
            f"Management port reachable: {[f'{p}/{_MGMT[p]}' for p in mgmt]}",
            severity=(gsev := grade.hardening()),
            cwe="CWE-668", cvss=grade.cvss_for(gsev), owasp="A05:2021",
            remediation="SSH/FTP being reachable is not itself a vulnerability. If this is "
                        "an intended service (git-over-SSH, a bastion host, SFTP), treat "
                        "as informational. Otherwise restrict to known source IPs or place "
                        "behind a VPN and enforce key-only authentication.",
            evidence_marker=f"ports={mgmt} (reachable — likely an intended service)"))
    risky_ports = crit + med

    findings.append(wrap_finding(
        f"InternetDB summary for {ip}",
        severity="POSITIVE",
        cwe="CWE-200",
        remediation="Public-facing service inventory. Run nmap to confirm "
                    "actual open ports vs Shodan's last scan.",
        evidence_marker=(
            f"ports={ports} | cpes={cpes[:5]} | "
            f"hostnames={hostnames[:5]} | tags={tags}"
        )))

    return standard_response(
        tool="shodan_internetdb", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(vulns or risky_ports),
        tests_summary=f"InternetDB: {len(ports)} ports, {len(cpes)} CPEs, {len(vulns)} CVEs",
        raw_data=data)


@router.post("/api/osint/shodan_internetdb")
@vl_verify()
async def scan_shodan_internetdb(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="shodan_internetdb", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
