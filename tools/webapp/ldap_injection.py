"""Webapp: LDAP filter injection detection."""
from fastapi import APIRouter, Depends
from urllib.parse import quote
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response

router = APIRouter()

_PARAMS = ["username","user","email","login","uid","cn","ou","search","filter","name"]
# (payload, description). Differential response vs baseline indicates LDAP processing.
_PAYLOADS = [
    ("*",                "wildcard - matches all entries"),
    ("*)(uid=*",         "filter break + always-true"),
    ("*)(|(uid=*",       "OR-injection always-true"),
    ("admin*",           "wildcard append"),
    (")(cn=*",           "filter close + wildcard"),
]


@router.post("/api/webapp/ldap_injection")
async def webapp_ldap_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    for param in _PARAMS:
        baseline = safe_get(f"{base}/?{param}=normaluser", req=req, timeout=8)
        if baseline is None or baseline.status_code >= 500:
            continue
        b_size = len(baseline.content)
        b_status = baseline.status_code
        for p, desc in _PAYLOADS:
            tests += 1
            r = safe_get(f"{base}/?{param}={quote(p)}", req=req, timeout=8)
            if r is None or r.status_code != b_status:
                continue
            # Significant size delta or response pattern change suggests LDAP processed input
            if abs(len(r.content) - b_size) < 200:
                continue
            # Skip if generic 4xx echo (often just template differences)
            findings.append(wrap_finding(
                f"Suspected LDAP injection - parameter '{param}' shows behavior change on filter payload",
                "HIGH",
                cvss="7.5", cwe="CWE-90",
                cwe_name="Improper Neutralization of Special Elements used in an LDAP Query",
                owasp="A03:2021",
                remediation=("Escape LDAP special chars: \\, *, (, ), NUL, /. Use parameterized "
                             "LDAP queries via your LDAP library's binding API instead of string "
                             "concatenation. Validate input against an allow-list (alphanumeric)."),
                evidence_marker=f"GET ?{param}=normaluser ({b_size}B) vs GET ?{param}={p} ({len(r.content)}B) - {desc}",
            ))
            break

    return standard_response(
        tool="ldap_injection", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"{tests} LDAP filter probes across {len(_PARAMS)} params x {len(_PAYLOADS)} payloads",
        raw_data={"ldap_injection": {"payloads_tested": [p for p,_ in _PAYLOADS]}},
    )


def register(app):
    app.include_router(router)
