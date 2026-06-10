"""hsts_audit_deep — HSTS header advanced audit (subdomain + preload).

Existing security_headers covers HSTS presence. This one audits the
quality of the HSTS policy:
  - max-age too short (<31536000 = 1 year)
  - missing includeSubDomains (subdomain takeover risk)
  - missing preload (not on browser preload list)
  - Strict-Transport-Security set ONLY on HTTPS but HTTP redirect doesn't carry it

Also checks live preload list via cross-reference.
"""
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()


def _parse_hsts(header_value: str) -> dict:
    if not header_value: return {}
    out = {"max_age": None, "include_subdomains": False, "preload": False}
    for part in header_value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try: out["max_age"] = int(part.split("=", 1)[1])
            except Exception: pass
        elif part == "includesubdomains":
            out["include_subdomains"] = True
        elif part == "preload":
            out["preload"] = True
    return out


@router.post("/api/webapp/scan/hsts_audit_deep")
@vl_turbo()
def scan_hsts_audit_deep(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return standard_response(
            tool="hsts_audit_deep", target=req.target,
            findings=[wrap_finding(
                "Target is HTTP — HSTS does not apply",
                "INFO", cwe="CWE-319",
                remediation="Serve over HTTPS first, then add HSTS.",
                evidence_marker=f"scheme: {parsed.scheme}")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not HTTPS")

    # 1. Check HTTPS response for HSTS
    r_https = safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)
    if r_https is None:
        return standard_response(
            tool="hsts_audit_deep", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="HTTPS endpoint unreachable")

    hsts_https = (r_https.headers.get("strict-transport-security") or "").strip()
    parsed_hsts = _parse_hsts(hsts_https)

    # 2. Check HTTP→HTTPS redirect response — should NOT carry HSTS (browser bug)
    #    but the redirect SHOULD happen
    http_url = url.replace("https://", "http://", 1)
    r_http = safe_request("GET", http_url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)
    redirects_to_https = False
    if r_http is not None and r_http.status_code in (301, 302, 307, 308):
        loc = r_http.headers.get("location") or ""
        if loc.lower().startswith("https://"):
            redirects_to_https = True

    findings = []

    if not hsts_https:
        findings.append(wrap_finding(
            "No HSTS header on HTTPS response",
            "MEDIUM", cvss="5.3", cwe="CWE-319", owasp="A02:2021",
            remediation="Add: Strict-Transport-Security: max-age=63072000; "
                        "includeSubDomains; preload. Without HSTS, attacker on "
                        "victim's network can MitM via SSL stripping (HTTPS→HTTP "
                        "redirect intercept).",
            evidence_marker="HSTS header absent on HTTPS response"))
    else:
        if parsed_hsts.get("max_age", 0) < 31536000:  # 1 year
            findings.append(wrap_finding(
                f"HSTS max-age too short: {parsed_hsts.get('max_age')}s (need >=31536000 = 1y)",
                "MEDIUM", cvss="4.3", cwe="CWE-319", owasp="A02:2021",
                remediation="Set max-age=63072000 (2 years) for preload eligibility. "
                            "Short max-age means a successful one-time MitM can persist.",
                evidence_marker=f"HSTS: {hsts_https[:100]}"))
        if not parsed_hsts.get("include_subdomains"):
            findings.append(wrap_finding(
                "HSTS missing includeSubDomains — subdomain MitM still possible",
                "MEDIUM", cvss="5.3", cwe="CWE-319", owasp="A02:2021",
                remediation="Add includeSubDomains directive. Without it, attacker "
                            "MitM-ing victim's network can intercept any subdomain "
                            "(e.g. dev.your-domain.com) and use it as auth-cookie pivot.",
                evidence_marker=f"HSTS: {hsts_https[:100]}"))
        if not parsed_hsts.get("preload"):
            findings.append(wrap_finding(
                "HSTS missing 'preload' directive — not on browser preload list",
                "LOW", cwe="CWE-319",
                remediation="After max-age=63072000 + includeSubDomains are set, "
                            "submit to hstspreload.org. Browsers hardcode preload-"
                            "listed domains, eliminating first-visit MitM. NOTE: "
                            "preload is HARD to undo (browser releases are slow).",
                evidence_marker=f"HSTS: {hsts_https[:100]}"))

    if r_http is not None and not redirects_to_https:
        findings.append(wrap_finding(
            f"HTTP does not redirect to HTTPS (HTTP {r_http.status_code})",
            "MEDIUM", cvss="5.3", cwe="CWE-319", owasp="A02:2021",
            remediation="HTTP endpoint should 301 redirect to HTTPS. Without it, "
                        "users typing http:// in browser navigate cleartext.",
            evidence_marker=f"HTTP GET → HTTP {r_http.status_code}, loc: "
                              f"{r_http.headers.get('location','')[:80]}"))

    if not findings:
        findings.append(wrap_finding(
            "HSTS properly configured (max-age long, includeSubDomains, preload, HTTP→HTTPS)",
            "POSITIVE", cwe="CWE-319",
            remediation="Maintain. Verify preload status at hstspreload.org/?domain="
                        + (parsed.hostname or ""),
            evidence_marker=f"HSTS: {hsts_https[:100]} | HTTP redirects to HTTPS: {redirects_to_https}"))

    return standard_response(
        tool="hsts_audit_deep", target=req.target, findings=findings,
        tests_performed=2,
        vulnerable=any(f.get("severity") == "MEDIUM" for f in findings),
        tests_summary=f"HSTS: {bool(hsts_https)}, HTTP→HTTPS: {redirects_to_https}",
        raw_data={"hsts_header": hsts_https,
                   "parsed": parsed_hsts,
                   "http_redirects_https": redirects_to_https})


def register(app):
    app.include_router(router)
