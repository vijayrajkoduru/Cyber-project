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

    # FRESHNESS GATE: a stealer-log hit only warrants HIGH/CRITICAL when it is
    # RECENT (a compromise from 5 years ago is largely stale credentials). Pull
    # the most-recent compromise date from the stealers list; if none is
    # available, treat freshness as UNKNOWN and cap the grade.
    import datetime as _dt
    _recent = False
    _has_date = False
    _latest = ""
    for _s in stealers:
        d = (_s.get("date_compromised") or _s.get("date") or
             _s.get("last_seen") or "")
        d = str(d)[:10]
        if len(d) >= 7 and d[:4].isdigit():
            _has_date = True
            if d > _latest:
                _latest = d
    if _has_date:
        try:
            yr, mo = int(_latest[:4]), int(_latest[5:7] or "1")
            age_months = ((_dt.date.today().year - yr) * 12
                          + (_dt.date.today().month - mo))
            _recent = age_months <= 24
        except Exception:
            _recent = False

    # Only escalate when there ARE employee compromises AND they're recent.
    if employees >= 10 and _recent:
        severity, cvss = "CRITICAL", "9.0"
    elif employees >= 1 and _recent:
        severity, cvss = "HIGH", "7.5"
    elif employees >= 1:
        # employee hit but stale / unverified freshness
        severity, cvss = "LOW", "3.1"
    else:
        # only users / third-parties, or no freshness signal
        severity, cvss = "INFO", "0.0"
    _fresh_note = (f"latest_compromise={_latest}, recent(<=24mo)={_recent}"
                   if _has_date else "freshness UNKNOWN — validate before acting")
    findings = [wrap_finding(
        f"STEALER LOGS — {domain}: {employees} employee, {users} user, {third_party} third-party compromised endpoint(s)",
        severity=severity, cvss=cvss,
        cwe="CWE-522", owasp="A07:2021",
        remediation="EMPLOYEE compromises = potential active credential leak (every "
                    "saved password on their endpoint may be exposed). VALIDATE "
                    "freshness first; for recent hits force password reset for ALL "
                    "listed employees, audit recent logins for anomalies, mandate "
                    "EDR + browser-credential-manager replacement. USER compromises = "
                    "your customer's endpoint exposed YOUR app's credentials.",
        evidence_marker=(
            f"employees={employees} | users={users} | third_party={third_party} | "
            f"{_fresh_note} | "
            f"stealer_families={','.join(s.get('family','?') for s in stealers[:5])} "
            f"(via Hudson Rock Cavalier)"
        ))]

    return standard_response(
        tool="hudson_rock_cavalier", target=req.target, findings=findings,
        tests_performed=1,
        vulnerable=severity in ("HIGH", "CRITICAL"),  # only graded when recent + employee
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
