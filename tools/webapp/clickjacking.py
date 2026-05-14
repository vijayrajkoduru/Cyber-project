"""Clickjacking / UI Redress Scanner — pure-Python active probe.

Pattern: TEMPLATE for active-probe webapp tools.
Sends one HTTP GET, inspects X-Frame-Options + CSP frame-ancestors,
emits findings with active-verification evidence_marker stamps.
"""
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, safe_get,
    web_url, wrap_finding, standard_response,
)

router = APIRouter()


@router.post("/api/webapp/clickjacking")
async def webapp_clickjacking(req: ScanRequest, user=Depends(verify_scan_quota)):
    target = web_url(req.target)
    r = safe_get(target, retries=2, timeout=15, req=req)
    if r is None:
        return standard_response(
            tool="clickjacking", target=req.target, findings=[],
            tests_performed=1,
            tests_summary="1 GET on /",
            skipped_reason="Target unreachable after retries",
        )

    xfo = r.headers.get("X-Frame-Options", "").strip()
    csp = r.headers.get("Content-Security-Policy", "").strip().lower()
    findings = []

    # 1. Missing both protections — fully vulnerable
    if not xfo and "frame-ancestors" not in csp:
        findings.append(wrap_finding(
            "No X-Frame-Options and no CSP frame-ancestors — page can be "
            "embedded in any iframe",
            "MEDIUM", cvss="6.1", cwe="CWE-1021", cwe_name="Clickjacking",
            owasp="A05:2021",
            remediation="Add: X-Frame-Options: DENY  OR  CSP: frame-ancestors 'none'",
            evidence_marker=f"HTTP {r.status_code} on / — no XFO header, no CSP frame-ancestors",
        ))
    # 2. SAMEORIGIN only (subdomain attacks possible)
    elif xfo.lower() == "sameorigin":
        findings.append(wrap_finding(
            "X-Frame-Options: SAMEORIGIN — framing allowed from same origin "
            "(subdomain attacks possible)",
            "LOW", cvss="3.1", cwe="CWE-1021",
            cwe_name="Improper Frame Restriction", owasp="A05:2021",
            remediation="Upgrade to X-Frame-Options: DENY unless same-origin "
                        "framing is required.",
            evidence_marker=f"X-Frame-Options: SAMEORIGIN on {target}",
        ))
    # 3. ALLOW-FROM is obsolete
    elif xfo.lower().startswith("allow-from"):
        findings.append(wrap_finding(
            f"X-Frame-Options: {xfo} — ALLOW-FROM is obsolete and ignored "
            f"by Chrome/Firefox/Edge",
            "MEDIUM", cvss="5.4", cwe="CWE-1021",
            cwe_name="Obsolete Clickjacking Protection", owasp="A05:2021",
            remediation="Replace ALLOW-FROM with CSP frame-ancestors directive.",
            evidence_marker=f"X-Frame-Options: {xfo} (obsolete)",
        ))

    return standard_response(
        tool="clickjacking", target=req.target, findings=findings,
        tests_performed=1,
        tests_summary="1 GET on / — inspected X-Frame-Options header + "
                      "CSP frame-ancestors directive",
    )


def register(app):
    app.include_router(router)
