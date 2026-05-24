"""Webapp: CRLF injection (header splitting via %0d%0a)."""
import secrets
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding, standard_response

router = APIRouter()

_TEST_PARAMS = ["redirect","url","return","next","callback","redir","redirect_uri","u","link"]

# AI-curated 60-entry CRLF payload list — each entry: {payload, category, severity}
# Substituted into the canary template at scan time to combine AI breadth + freshness-check.
try:
    from tools._payloads.crlf_injection_payloads import CRLF_INJECTION_PAYLOADS as _AI_CRLF_PAYLOADS
    _AI_CRLF_RAW = [p.get("payload","") for p in _AI_CRLF_PAYLOADS if isinstance(p, dict) and p.get("payload")]
except Exception:
    _AI_CRLF_RAW = []


@router.post("/api/webapp/crlf_injection")
async def webapp_crlf_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    canary_name = "vlcrlf" + secrets.token_hex(4)
    canary_value = "polluted-" + secrets.token_hex(4)
    
    payloads = [
        f"%0d%0aSet-Cookie:%20{canary_name}={canary_value}",
        f"%0aSet-Cookie:%20{canary_name}={canary_value}",
        f"%E5%98%8A%E5%98%8DSet-Cookie:%20{canary_name}={canary_value}",  # UTF-8 CRLF bypass
    ]
    # Append AI-curated CRLF variants — combine each AI sequence with the canary
    # so we still catch echo even if scanner doesn't know the exact AI payload shape.
    for ai in _AI_CRLF_RAW[:15]:  # cap to keep wave size sane
        if "%0d%0a" in ai or "%0a" in ai or "\r\n" in ai:
            payloads.append(f"{ai}Set-Cookie:%20{canary_name}={canary_value}")
    
    suspect = []
    for param in _TEST_PARAMS:
        for p in payloads:
            tests += 1
            url = f"{base}/?{param}=foo{p}"
            try:
                r = requests.get(url, timeout=8, allow_redirects=False, verify=False,
                                 headers={"User-Agent":"VulnusLab/1.0"})
            except Exception:
                continue
            # Check if Set-Cookie containing our canary appears in response headers
            for hk, hv in r.headers.items():
                if hk.lower() == "set-cookie" and canary_name in hv and canary_value in hv:
                    suspect.append({"param": param, "payload": p, "header": f"{hk}: {hv[:80]}"})
                    findings.append(wrap_finding(
                        f"CRLF injection - parameter '{param}' allows header injection via %0d%0a",
                        "HIGH",
                        cvss="7.5", cwe="CWE-93",
                        cwe_name="Improper Neutralization of CRLF Sequences (HTTP Response Splitting)",
                        owasp="A03:2021",
                        remediation=("Strip or reject \\r and \\n characters in any user input that flows "
                                     "into response headers (Location, Set-Cookie, custom headers). Most "
                                     "modern frameworks block this automatically - if you see this, you "
                                     "are likely concatenating user input into raw HTTP responses."),
                        evidence_marker=f"GET {url} -> response includes injected Set-Cookie: {canary_name}={canary_value}",
                    ))
                    break

    return standard_response(
        tool="crlf_injection", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"{tests} CRLF probes across {len(_TEST_PARAMS)} params x {len(payloads)} encodings",
        raw_data={"crlf_injection": {"suspect": suspect, "canary": canary_name}},
    )


def register(app):
    app.include_router(router)
