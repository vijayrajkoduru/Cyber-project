"""Hudson Rock Cavalier free stealer-log check — playbook §5 #71.

Hudson Rock's Cavalier API exposes a free endpoint that reports whether
a domain has appeared in info-stealer logs (RedLine, Vidar, Raccoon,
Stealc, etc). These are credentials harvested by malware on victim
endpoints — different from corporate breaches.

Real probe. Zero false positives. Free, no key.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 12


def _clean(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    return t.lower()


def _do_scan(req: ScanRequest) -> dict:
    domain = _clean((req.target or "").strip())
    if not domain or "." not in domain:
        return standard_response(
            tool="hudson_rock_cavalier", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid domain")

    r = safe_get(
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}",
        req=req, timeout=10,
        headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="hudson_rock_cavalier", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Hudson Rock unreachable (status={r.status_code if r else 'no-conn'})")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="hudson_rock_cavalier", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON Hudson Rock response")

    employees = data.get("total_employees") or 0
    users = data.get("total_users") or 0
    third_party = data.get("total_third_parties") or 0
    stealers = data.get("stealers") or []

    total = employees + users + third_party
    if total == 0:
        return standard_response(
            tool="hudson_rock_cavalier", target=req.target,
            findings=[wrap_finding(
                f"{domain} has 0 stealer-log compromises in Hudson Rock",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="No employees, users, or third-parties found in "
                            "Hudson Rock's stealer-log corpus. Re-check monthly.",
                evidence_marker="Cavalier returned 0 across all categories (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Clean per Hudson Rock")

    severity = "CRITICAL" if employees >= 10 else "HIGH" if employees >= 1 else "MEDIUM"
    findings = [wrap_finding(
        f"STEALER LOGS — {domain}: {employees} employee, {users} user, {third_party} third-party compromised endpoint(s)",
        severity=severity, cvss="9.0" if employees else "6.5",
        cwe="CWE-522", owasp="A07:2021",
        remediation="EMPLOYEE compromises = active credential leak (every saved "
                    "password on their endpoint is exposed). Force password reset for "
                    "ALL listed employees, audit recent logins for anomalies, mandate "
                    "EDR + browser-credential-manager replacement. USER compromises = "
                    "your customer's endpoint exposed YOUR app's credentials.",
        evidence_marker=(
            f"employees={employees} | users={users} | third_party={third_party} | "
            f"stealer_families={','.join(s.get('family','?') for s in stealers[:5])} "
            f"(CONFIRMED via Hudson Rock Cavalier)"
        ))]

    return standard_response(
        tool="hudson_rock_cavalier", target=req.target, findings=findings,
        tests_performed=1, vulnerable=True,
        tests_summary=f"Hudson Rock: {employees}/{users}/{third_party} compromises",
        raw_data=data)


@router.post("/api/osint/hudson_rock_cavalier")
@vl_verify()
async def scan_hudson_rock_cavalier(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="hudson_rock_cavalier", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
