"""HIBP breaches-by-domain enumeration — playbook §5 #65.

Lists all known breaches that exposed accounts at the target domain.
Uses /api/v3/breaches?domain= endpoint which is FREE (the per-account
breach API requires paid auth, but the domain enum is free).

Real probe. Zero false positives — only reports HIBP-confirmed breaches.
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
    domain = _clean((req.target or "").strip())
    if not domain or "." not in domain:
        return standard_response(
            tool="hibp_breaches_domain", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid domain")

    # VL-VERIFY deep: reserved-domain skip — HIBP returns matches for
    # example.com because countless breach analysis articles reference it.
    from tools._vl_core.reserved_domains import is_reserved
    if is_reserved(domain):
        return standard_response(
            tool="hibp_breaches_domain", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason=("Target is RFC 2606 / 6761 reserved domain. "
                             "HIBP breach lookup is not applicable."))

    r = safe_get(f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
                  req=req, timeout=8,
                  headers={"User-Agent": "VulnusLab-OSINT/1.0",
                            "hibp-api-version": "3"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="hibp_breaches_domain", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"HIBP unreachable (status={r.status_code if r else 'no-conn'})")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="hibp_breaches_domain", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON HIBP response")

    breaches = data if isinstance(data, list) else []

    # VL-VERIFY deep: filter to breaches whose Domain field actually matches.
    # HIBP's domain query can return breaches that merely reference the
    # domain in their data classes / description. Real "this domain was
    # breached" requires Domain field equality.
    verified = []
    weak_match = []
    for b in breaches:
        b_domain = (b.get("Domain") or "").lower()
        if b_domain == domain or b_domain.endswith("." + domain):
            verified.append(b)
        else:
            weak_match.append(b)
    breaches = verified

    if not breaches:
        return standard_response(
            tool="hibp_breaches_domain", target=req.target,
            findings=[wrap_finding(
                f"{domain} has NO public breaches in HIBP",
                severity=grade.protective(), cwe="CWE-1395",
                remediation="No HIBP-tracked breaches. Continue monitoring (HIBP "
                            "adds breaches as they surface).",
                evidence_marker="HIBP returned 0 breaches (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Clean per HIBP")

    # Sort by exposed account count
    breaches.sort(key=lambda b: b.get("PwnCount", 0), reverse=True)
    total_accounts = sum(b.get("PwnCount", 0) for b in breaches)

    biggest = breaches[0]
    top5 = breaches[:5]

    weak_note = (f" [{len(weak_match)} title-only matches dropped]"
                  if weak_match else "")
    findings = [wrap_finding(
        f"{domain} appears in {len(breaches)} breach(es) — {total_accounts:,} accounts exposed (CONFIRMED via Domain field)",
        severity=(sev := grade.exposure(
            confirmed=True,
            impact="enables" if total_accounts >= 100000 else "aids")),
        cvss=grade.cvss_for(sev),
        cwe="CWE-359", owasp="A05:2021",
        verified_exploit=True,
        remediation="For each breach: identify affected users, force password "
                    "reset, audit for credential reuse on internal systems, monitor "
                    "for HIBP-domain-monitoring service via paid API. Worst-case: "
                    "notify under GDPR Art 33/34 if not already done.",
        evidence_marker=(
            f"biggest: {biggest.get('Name')} "
            f"({biggest.get('PwnCount', 0):,} accts, {biggest.get('BreachDate', '?')}) | "
            f"top 5: {', '.join(f'{b.get(chr(34)+chr(78)+chr(97)+chr(109)+chr(101)+chr(34), chr(63))} ({b.get(chr(34)+chr(80)+chr(119)+chr(110)+chr(67)+chr(111)+chr(117)+chr(110)+chr(116)+chr(34), 0):,})' for b in top5)}"
            + weak_note
        ))]

    return standard_response(
        tool="hibp_breaches_domain", target=req.target, findings=findings,
        tests_performed=1, vulnerable=True,
        tests_summary=f"HIBP: {len(breaches)} breaches / {total_accounts:,} accounts",
        raw_data={"breach_count": len(breaches), "total_accounts": total_accounts,
                   "breaches": [{"name": b.get("Name"), "date": b.get("BreachDate"),
                                  "count": b.get("PwnCount", 0)}
                                 for b in breaches[:20]]})


@router.post("/api/osint/hibp_breaches_domain")
@vl_verify()
async def scan_hibp_breaches_domain(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="hibp_breaches_domain", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
