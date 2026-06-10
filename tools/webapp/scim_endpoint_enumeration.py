"""scim_endpoint_enumeration — SCIM 2.0 endpoint discovery + auth audit.

SCIM (System for Cross-domain Identity Management) is the standard
provisioning API for SSO. Endpoints: /scim/v2/Users, /scim/v2/Groups.
Common bug: SCIM requires Bearer auth, but path is exposed without
authentication enforcement → attacker enumerates user list with PII.
"""
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

SCIM_PATHS = [
    "/scim/v2/", "/scim/v2/Users", "/scim/v2/Groups",
    "/scim/v2/ServiceProviderConfig", "/scim/v2/ResourceTypes",
    "/scim/v2/Schemas",
    "/api/scim/v2/Users", "/.well-known/scim",
]


@router.post("/api/webapp/scan/scim_endpoint_enumeration")
@vl_turbo()
@vl_verify()
def scan_scim_endpoint_enumeration(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    discovered = []
    unauth_exposed = []
    user_count = None

    for path in SCIM_PATHS:
        url = base + path
        # Unauth probe
        r = safe_request("GET", url,
            headers={"User-Agent": "VulnusLab/1.0",
                      "Accept": "application/scim+json,application/json"},
            req=req, timeout=8, allow_redirects=False)
        if r is None or r.status_code == 404: continue

        # Did we get a SCIM-style response?
        try:
            data = r.json()
        except Exception:
            data = {}

        is_scim = (isinstance(data, dict) and
                    ("schemas" in data or "Resources" in data or
                     "totalResults" in data))
        if is_scim:
            discovered.append({"path": path, "status": r.status_code})
            # Unauth + 200 = bug
            if r.status_code == 200:
                unauth_exposed.append({"path": path,
                                         "total_results": data.get("totalResults", 0)})
                if path.endswith("/Users") and "totalResults" in data:
                    user_count = data["totalResults"]
        elif r.status_code in (401, 403):
            # SCIM with auth required (good)
            discovered.append({"path": path, "status": r.status_code,
                                 "note": "auth-required"})

    findings = []
    if unauth_exposed:
        findings.append(wrap_finding(
            f"SCIM endpoint(s) accessible WITHOUT auth ({len(unauth_exposed)})",
            "HIGH", cvss="8.6", cwe="CWE-306", owasp="A01:2021",
            remediation="SCIM endpoints expose user/group provisioning data — must "
                        "require Bearer token. Configure SCIM SP to enforce auth on "
                        "every /scim/v2/* path. If using Okta/Azure AD as IdP, the "
                        "Bearer token shared with the SP must be required server-side. "
                        + (f"Currently leaks {user_count} user records." if user_count else ""),
            evidence_marker=" | ".join(
                f"{e['path']}: HTTP 200, totalResults={e['total_results']}"
                for e in unauth_exposed[:3]
            )))
    elif discovered:
        findings.append(wrap_finding(
            f"SCIM endpoints discovered ({len(discovered)}) — all auth-protected",
            "POSITIVE", cwe="CWE-306",
            remediation="Maintain. Rotate Bearer tokens shared with IdP periodically.",
            evidence_marker=" | ".join(
                f"{d['path']}: HTTP {d['status']}" for d in discovered[:5]
            )))
    else:
        return standard_response(
            tool="scim_endpoint_enumeration", target=req.target,
            findings=[wrap_finding(
                "No SCIM endpoints detected",
                "POSITIVE", cwe="CWE-200",
                remediation="No SCIM attack surface from this scan.",
                evidence_marker=f"checked {len(SCIM_PATHS)} common SCIM paths")],
            tests_performed=len(SCIM_PATHS), vulnerable=False,
            tests_summary="No SCIM")

    return standard_response(
        tool="scim_endpoint_enumeration", target=req.target, findings=findings,
        tests_performed=len(SCIM_PATHS), vulnerable=bool(unauth_exposed),
        tests_summary=f"discovered: {len(discovered)}, unauth: {len(unauth_exposed)}",
        raw_data={"discovered": discovered, "unauth_exposed": unauth_exposed,
                   "user_count": user_count})


def register(app):
    app.include_router(router)
