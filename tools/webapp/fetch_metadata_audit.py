"""fetch_metadata_audit — Sec-Fetch-* header trust audit.

Sec-Fetch-Site / Sec-Fetch-Mode / Sec-Fetch-Dest are browser-set headers
that indicate the request's CONTEXT (same-origin, cross-site, etc).
Modern apps use them as a CSRF defense: reject state-changing requests
where Sec-Fetch-Site is 'cross-site' but the path needs auth.

Audit: send a POST with Sec-Fetch-Site: cross-site to a state-changing
endpoint. If accepted (without CSRF token), the app isn't using Fetch
Metadata defense.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

# State-changing endpoints
STATE_PATHS = [
    "/api/transfer", "/api/users", "/api/admin",
    "/api/settings", "/api/logout", "/logout",
    "/api/account/delete", "/api/posts",
]


@router.post("/api/webapp/scan/fetch_metadata_audit")
@vl_turbo()
def scan_fetch_metadata_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    issues = []
    tested = 0

    for path in STATE_PATHS:
        url = base + path
        # Sanity: does endpoint exist? (HEAD or OPTIONS)
        r0 = safe_request("OPTIONS", url,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=6, allow_redirects=False)
        if r0 is None or r0.status_code == 404: continue
        tested += 1

        # Probe 1: cross-site Sec-Fetch headers
        r1 = safe_request("POST", url,
            headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0",
                      "Content-Type": "application/json",
                      "Sec-Fetch-Site": "cross-site",
                      "Sec-Fetch-Mode": "cors",
                      "Sec-Fetch-Dest": "empty",
                      "Origin": "https://evil-attacker.example"},
            data='{"vulnuslab":"probe"}', req=req, timeout=8,
            allow_redirects=False)
        if r1 is None: continue
        # 200/302 with this set = no Fetch Metadata defense
        if r1.status_code in (200, 302, 201, 204):
            issues.append({"path": path, "status": r1.status_code,
                            "issue": "accepts cross-site POST"})

    if issues:
        findings.append(wrap_finding(
            f"No Fetch Metadata defense — {len(issues)} state-changing endpoint(s) "
            "accept cross-site requests",
            "MEDIUM", cvss="5.3", cwe="CWE-352", owasp="A01:2021",
            remediation="Add Fetch Metadata resource isolation policy: middleware "
                        "rejects state-changing requests when Sec-Fetch-Site is "
                        "'cross-site' AND Sec-Fetch-Mode is 'no-cors' or 'cors' "
                        "(unless explicitly allowed). Defense in depth alongside "
                        "CSRF tokens. Reference: web.dev/fetch-metadata.",
            evidence_marker=" | ".join(
                f"{i['path']}: HTTP {i['status']} on cross-site POST" for i in issues[:5]
            )))
    elif tested > 0:
        findings.append(wrap_finding(
            f"Fetch Metadata defense appears active ({tested} state-paths checked)",
            "POSITIVE", cwe="CWE-352",
            remediation="Maintain. Continue rejecting cross-site state changes.",
            evidence_marker=f"{tested} state-changing paths × cross-site POST = rejected"))
    else:
        return standard_response(
            tool="fetch_metadata_audit", target=req.target, findings=[],
            tests_performed=len(STATE_PATHS), vulnerable=False,
            skipped_reason="No state-changing endpoints found at common paths")

    return standard_response(
        tool="fetch_metadata_audit", target=req.target, findings=findings,
        tests_performed=tested * 2, vulnerable=bool(issues),
        tests_summary=f"{tested} endpoints, {len(issues)} accept cross-site",
        raw_data={"issues": issues})


def register(app):
    app.include_router(router)
