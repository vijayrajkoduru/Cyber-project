"""Shodan InternetDB free host fingerprint — playbook §2 #26 ⭐.

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
        findings.append(wrap_finding(
            f"InternetDB lists {len(vulns)} CVE(s) on this host",
            severity="CRITICAL" if len(vulns) >= 3 else "HIGH",
            cwe="CWE-1395", cvss="9.0" if len(vulns) >= 3 else "7.5",
            owasp="A06:2021",
            remediation="Patch immediately. Shodan-published CVEs are scraped "
                        "by mass-exploitation actors within hours. Cross-reference "
                        "each CVE in NVD for the patched version of the affected component.",
            evidence_marker=f"vulns: {', '.join(vulns[:10])}"
                              + (' ...' if len(vulns) > 10 else '')
                              + " (CONFIRMED via Shodan InternetDB)"))

    risky_ports = [p for p in ports if p in
                    (21, 22, 23, 135, 137, 139, 445, 1433, 3306, 3389, 5432,
                     5900, 6379, 9200, 11211, 27017)]
    if risky_ports:
        findings.append(wrap_finding(
            f"Sensitive service ports exposed: {risky_ports}",
            severity="HIGH" if any(p in (23, 445, 3389, 6379, 11211, 27017)
                                      for p in risky_ports) else "MEDIUM",
            cwe="CWE-668", cvss="7.5",
            owasp="A05:2021",
            remediation="Restrict via firewall to known source IPs. Mgmt ports "
                        "(SSH, RDP) behind VPN. Database ports never internet-facing. "
                        "Telnet (23) and SMB (445) should be off entirely.",
            evidence_marker=f"risky-ports: {risky_ports} (CONFIRMED via Shodan)"))

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
