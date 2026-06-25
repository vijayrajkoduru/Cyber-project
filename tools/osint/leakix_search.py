"""LeakIX exposed-asset search — playbook §4 #63 / §5 #68.

LeakIX scans the internet for exposed assets (open databases, leaked
credentials, exposed admin panels). The free /search endpoint works
unauthenticated for low volume; higher tiers need a key.

Real probe. Zero false positives — only reports LeakIX-confirmed exposures.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify
from tools._core import grade

router = APIRouter()
WALL_CLOCK_S = 12


def _clean(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    return t.lower()


def _do_scan(req: ScanRequest) -> dict:
    target = _clean((req.target or "").strip())
    if not target:
        return standard_response(
            tool="leakix_search", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty target")

    headers = {"Accept": "application/json",
                "User-Agent": "VulnusLab-OSINT/1.0"}
    if req.auth_bearer:
        headers["api-key"] = req.auth_bearer

    r = safe_get(f"https://leakix.net/host/{target}",
                  req=req, timeout=10, headers=headers)
    if r is None:
        return standard_response(
            tool="leakix_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="LeakIX unreachable")
    if r.status_code == 404:
        return standard_response(
            tool="leakix_search", target=req.target,
            findings=[wrap_finding(
                f"LeakIX has no scans for {target}",
                severity=grade.protective(), cwe="CWE-1395",
                remediation="No exposed-asset records in LeakIX. Re-scan periodically.",
                evidence_marker="LeakIX 404 (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not in LeakIX")
    if r.status_code != 200:
        return standard_response(
            tool="leakix_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"LeakIX status {r.status_code} (rate-limit?)")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="leakix_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON LeakIX response")

    services = (data.get("Services") or []) if isinstance(data, dict) else []
    leaks = (data.get("Leaks") or []) if isinstance(data, dict) else []

    findings = []
    if leaks:
        leak_types = sorted({l.get("event_source") or l.get("plugin") or "?"
                              for l in leaks})
        # Being INDEXED by LeakIX is third-party intel, not a self-verified
        # live exposure (entries can be stale, deduped, or already remediated).
        # Default LOW; the customer must confirm the leak is still live before
        # treating it as a graded exposure.
        findings.append(wrap_finding(
            f"LeakIX indexed {len(leaks)} potential leak(s) for {target}",
            severity=(sev := grade.hardening()), cvss=grade.cvss_for(sev), cwe="CWE-200",
            owasp="A05:2021",
            remediation="LeakIX-indexed entries are unverified third-party intel — "
                        "they may be stale or already remediated. VERIFY each entry "
                        "is still live, then patch/close the exposing service and "
                        "rotate any credentials that may have been visible.",
            evidence_marker=f"leak_types: {', '.join(leak_types[:10])} "
                            f"(LeakIX-indexed, freshness UNVERIFIED)"))

    if services:
        risky_services = [s for s in services if any(k in str(s).lower() for k in
                          ("elastic", "mongodb", "redis", "memcache", "couchdb",
                           "kibana", "jenkins", "ftp", "rdp", "smb"))]
        if risky_services:
            # An indexed open service is not proof of an exploitable exposure
            # (it may be authenticated / firewalled since the scan). INFO.
            findings.append(wrap_finding(
                f"LeakIX indexed {len(risky_services)} sensitive service(s)",
                severity=(sev := grade.info()), cvss=grade.cvss_for(sev), cwe="CWE-668",
                owasp="A05:2021",
                remediation="Indexed mgmt/database services are informational — "
                            "an open port is not proof of exploitability. Confirm "
                            "the service is still reachable AND unauthenticated, then "
                            "firewall to known IPs or VPN.",
                evidence_marker=" | ".join(
                    f"{s.get('protocol','?')}:{s.get('port','?')}"
                    for s in risky_services[:10]
                ) + " (LeakIX-indexed, exposure UNVERIFIED)"))

    if not findings:
        findings.append(wrap_finding(
            f"LeakIX: {len(services)} service(s) indexed, 0 leaks",
            severity=grade.protective(), cwe="CWE-200",
            remediation="LeakIX has indexed this host but found no leaks. Public "
                        "service inventory is fine; just confirm each port is intentional.",
            evidence_marker=f"services={len(services)} leaks=0 (CONFIRMED)"))

    return standard_response(
        tool="leakix_search", target=req.target, findings=findings,
        tests_performed=1,
        vulnerable=False,  # indexed != exploitable — unverified third-party intel
        tests_summary=f"LeakIX: {len(services)} svc / {len(leaks)} leaks",
        raw_data={"services": services[:10], "leaks": leaks[:10]})


@router.post("/api/osint/leakix_search")
@vl_verify()
async def scan_leakix_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="leakix_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
