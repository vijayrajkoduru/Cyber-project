"""Webapp: Host header injection / X-Forwarded-Host abuse."""
import secrets
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding, standard_response

router = APIRouter()


@router.post("/api/webapp/host_header_injection")
async def webapp_host_header_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    canary = "vulnuslab-" + secrets.token_hex(4) + ".attacker.example"
    
    test_cases = [
        ("Host", {"Host": canary}),
        ("X-Forwarded-Host", {"X-Forwarded-Host": canary}),
        ("X-Host", {"X-Host": canary}),
        ("X-Forwarded-Server", {"X-Forwarded-Server": canary}),
        ("X-Original-URL", {"X-Original-URL": f"http://{canary}/"}),
        ("X-Rewrite-URL", {"X-Rewrite-URL": f"http://{canary}/"}),
    ]
    
    suspect = []
    for header_name, headers in test_cases:
        tests += 1
        try:
            r = requests.get(base + "/", headers={**headers, "User-Agent": "VulnusLab/1.0"},
                             timeout=8, allow_redirects=False, verify=False)
        except Exception:
            continue
        # Check for canary in response body OR Location header (redirect)
        body = (r.text or "")[:20000]
        loc = r.headers.get("Location", "")
        if canary in body or canary in loc:
            where = "body" if canary in body else "Location header"
            suspect.append({"header": header_name, "reflected_in": where})
            findings.append(wrap_finding(
                f"Host header injection - '{header_name}: {canary}' reflected in {where}",
                "HIGH",
                cvss="7.4", cwe="CWE-20",
                cwe_name="Improper Input Validation",
                owasp="A03:2021",
                remediation="Validate Host header against an allow-list of expected hostnames. Reject requests with untrusted Host headers. Use absolute URLs from server config, not from request headers.",
                evidence_marker=f"Sent {header_name}: {canary} -> canary appeared in {where}",
            ))

    return standard_response(
        tool="host_header_injection", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Tested {tests} Host header variants with unique canary",
        raw_data={"host_header_injection": {"canary": canary, "suspect": suspect}},
    )


def register(app):
    app.include_router(router)
