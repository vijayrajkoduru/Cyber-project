"""breach_check — HaveIBeenPwned breach lookup for target domain.

Uses the free HIBP "breach by domain" endpoint (no key needed — only the
account-level endpoint requires a key). Returns all known breaches that
include credentials from the target's email domain.

VL-FOUNDRY Layer 6: 7-check DoD compliant.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 12


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip().lower()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    if "." not in target:
        return standard_response(tool="breach_check", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="target must be a domain")

    # VL-VERIFY deep: reserved-domain skip (decorator covers it but be explicit
    # so the response carries the reason)
    from tools._vl_core.reserved_domains import is_reserved
    if is_reserved(target):
        return standard_response(tool="breach_check", target=req.target,
            findings=[], tests_performed=0, vulnerable=False,
            skipped_reason=("Target is RFC 2606 / 6761 reserved domain. "
                             "Breach lookup is not applicable."))

    # Public domain endpoint — no auth required
    url = f"https://haveibeenpwned.com/api/v3/breaches?domain={target}"
    r = safe_get(url, req=req, timeout=8,
                 headers={"User-Agent": "VulnusLab-OSINT",
                          "hibp-api-version": "3"})

    if r is None:
        return standard_response(tool="breach_check", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="HIBP unreachable")
    if r.status_code == 404:
        # 404 = no breaches found (HIBP returns 404 instead of empty array)
        breaches = []
    elif r.status_code != 200:
        return standard_response(tool="breach_check", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"HIBP returned status {r.status_code}")
    else:
        try:
            breaches = r.json() or []
        except Exception:
            breaches = []

    # VL-VERIFY deep: filter breaches to those whose Domain field actually
    # matches the target. HIBP's /breaches?domain= endpoint sometimes returns
    # breaches that reference the domain in their data classes but aren't
    # actually FROM that domain. We require Domain field equality.
    verified_breaches = []
    weak_match = []
    for b in breaches:
        b_domain = (b.get("Domain") or "").lower()
        if b_domain == target or b_domain.endswith("." + target):
            verified_breaches.append(b)
        elif target in str(b.get("Title", "")).lower() or target in str(b.get("Description", "")).lower():
            weak_match.append(b)

    findings = []
    if verified_breaches:
        sample = [f"{b.get('Name', '?')} ({b.get('BreachDate', '?')}, "
                  f"{b.get('PwnCount', 0):,} accounts)" for b in verified_breaches[:5]]
        total = sum(b.get("PwnCount", 0) for b in verified_breaches)
        sensitive = any(b.get("IsSensitive") for b in verified_breaches)
        sev = "HIGH" if sensitive or total > 100000 else "MEDIUM"
        weak_note = (f" [{len(weak_match)} additional title-only matches dropped]"
                      if weak_match else "")
        findings.append(wrap_finding(
            f"{len(verified_breaches)} breach(es) include credentials from {target} "
            f"(total: {total:,} accounts) (CONFIRMED via Domain field)",
            sev, cvss="7.5" if sev == "HIGH" else "5.5",
            cwe="CWE-200", owasp="A07:2021",
            verified_exploit=True,
            remediation=("Force password rotation for all users on this domain. "
                        "Enroll MFA. Subscribe to HIBP's domain-monitoring alerts "
                        "for breach notification within 24 hours of public disclosure."),
            evidence_marker="; ".join(sample) + weak_note))
    elif weak_match:
        # Breach mentioned domain but Domain field didn't match — SUSPECTED only.
        sample = [b.get("Name", "?") for b in weak_match[:5]]
        findings.append(wrap_finding(
            f"{len(weak_match)} breach(es) mention {target} (SUSPECTED, title/description match only)",
            severity="LOW", cvss="3.1",
            cwe="CWE-200", owasp="A07:2021",
            remediation="Manually review each breach; Domain field did not match target.",
            evidence_marker="; ".join(sample)))
    else:
        findings.append(wrap_finding(
            "No breaches in HIBP reference this domain",
            severity="POSITIVE",
            cwe="CWE-200", owasp="A07:2021",
            remediation="No known breach exposure — subscribe to HIBP domain "
                        "monitoring to get notified on future breaches.",
            evidence_marker="HIBP breach API returned 0 breaches"))

    return standard_response(
        tool="breach_check", target=req.target, findings=findings,
        tests_performed=1,
        vulnerable=len(breaches) > 0,
        tests_summary=f"HIBP breach-by-domain: {len(breaches)} known breaches",
        raw_data={"breaches": [{k: b.get(k) for k in
                                ("Name", "Title", "Domain", "BreachDate",
                                 "PwnCount", "IsSensitive", "DataClasses")}
                                for b in breaches[:20]]})


@router.post("/api/osint/breach_check")
@vl_verify()
async def scan_breach(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="breach_check", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
