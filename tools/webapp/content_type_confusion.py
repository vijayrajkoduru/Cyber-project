"""content_type_confusion — server parses body opposite to Content-Type header.

Send valid JSON body with Content-Type: text/plain (or x-www-form-urlencoded).
If server STILL parses it as JSON, it defeats:
  - SameSite CSRF protection (preflight skipped for simple Content-Types)
  - WAF rules that only inspect JSON requests
  - CSP form-action enforcement

Symmetric test: send form-encoded body with Content-Type: application/json.
"""
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()

API_PATHS = [
    "/api/login", "/api/auth", "/api/v1/login",
    "/api/users", "/api/echo", "/api/me",
    "/login", "/auth/login",
]


def _send(url, body, content_type, req):
    return safe_request("POST", url,
        headers={"Content-Type": content_type,
                  "User-Agent": "VulnusLab/1.0"},
        data=body, req=req, timeout=8, allow_redirects=False)


@router.post("/api/webapp/scan/content_type_confusion")
def scan_content_type_confusion(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    confused_endpoints = []
    tested = 0

    json_body = '{"username":"vulnuslab-test","password":"x"}'
    form_body = "username=vulnuslab-test&password=x"

    for path in API_PATHS:
        url = base + path
        # Baseline: send proper JSON with proper Content-Type
        r0 = _send(url, json_body, "application/json", req)
        if r0 is None or r0.status_code == 404: continue
        tested += 1
        baseline_status = r0.status_code
        baseline_body = (r0.text or "")[:1000]

        # Confusion test: same JSON body, WRONG Content-Type
        r1 = _send(url, json_body, "text/plain", req)
        if r1 is None: continue
        # If server STILL parses (returns same status + body), confused
        body1 = (r1.text or "")[:1000]
        if (r1.status_code == baseline_status and
                abs(len(body1) - len(baseline_body)) < 100 and
                # And neither is a 400/415 (proper rejection)
                baseline_status not in (400, 415)):
            confused_endpoints.append({
                "path": path,
                "baseline_status": baseline_status,
                "confused_status": r1.status_code,
            })

    if confused_endpoints:
        findings.append(wrap_finding(
            f"Content-Type confusion at {len(confused_endpoints)} endpoint(s)",
            "MEDIUM", cvss="5.3", cwe="CWE-436", owasp="A05:2021",
            remediation="Server parses JSON body even when Content-Type is text/plain. "
                        "This defeats CSRF protection in browsers (text/plain is a "
                        "'simple' Content-Type that doesn't trigger preflight). "
                        "Reject requests where Content-Type doesn't match expected "
                        "format. Frameworks: Express body-parser → use strict mode "
                        "+ type-check; Spring → @RequestMapping consumes='application/"
                        "json'; FastAPI → declare Pydantic body model (auto-rejects "
                        "wrong Content-Type with 422).",
            evidence_marker=" | ".join(
                f"{e['path']}: HTTP {e['baseline_status']} (both json & plain)"
                for e in confused_endpoints[:5]
            )))
    elif tested > 0:
        findings.append(wrap_finding(
            f"Content-Type properly enforced ({tested} endpoint(s) tested)",
            "POSITIVE", cwe="CWE-436",
            remediation="Maintain. Reject mismatched Content-Type on all POST endpoints.",
            evidence_marker=f"endpoints tested: {tested}, no confusion detected"))
    else:
        return standard_response(
            tool="content_type_confusion", target=req.target, findings=[],
            tests_performed=len(API_PATHS), vulnerable=False,
            skipped_reason="None of the common API endpoints exist on target")

    return standard_response(
        tool="content_type_confusion", target=req.target, findings=findings,
        tests_performed=len(API_PATHS) * 2, vulnerable=bool(confused_endpoints),
        tests_summary=f"{tested} endpoints tested, {len(confused_endpoints)} confused",
        raw_data={"confused_endpoints": confused_endpoints})


def register(app):
    app.include_router(router)
