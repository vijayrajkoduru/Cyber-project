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

    findings = []
    if breaches:
        sample = [f"{b.get('Name', '?')} ({b.get('BreachDate', '?')}, "
                  f"{b.get('PwnCount', 0):,} accounts)" for b in breaches[:5]]
        total = sum(b.get("PwnCount", 0) for b in breaches)
        sensitive = any(b.get("IsSensitive") for b in breaches)
        sev = "HIGH" if sensitive or total > 100000 else "MEDIUM"
        findings.append(wrap_finding(
            f"{len(breaches)} breach(es) include credentials from {target} "
            f"(total: {total:,} accounts)",
            sev, cvss="7.5" if sev == "HIGH" else "5.5",
            cwe="CWE-200", owasp="A07:2021",
            remediation=("Force password rotation for all users on this domain. "
                        "Enroll MFA. Subscribe to HIBP's domain-monitoring alerts "
                        "for breach notification within 24 hours of public disclosure."),
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
