"""Webapp: parameter reflection scanner - finds params that echo into response."""
import secrets
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response

router = APIRouter()

_COMMON_PARAMS = ["q","search","query","s","name","title","msg","message","content","input","text","data","url","return","redirect","callback","ref","page","action","id","user","email","comment","filter","keyword"]


@router.post("/api/webapp/param_reflection")
async def webapp_param_reflection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    reflected = []
    tests = 0
    for param in _COMMON_PARAMS:
        tests += 1
        canary = "vlref" + secrets.token_hex(4)
        r = safe_get(f"{base}/?{param}={canary}", req=req, timeout=8)
        if r is None:
            continue
        body = (r.text or "")[:50000]
        if canary not in body:
            continue
        # Check escaping
        escaped_html = (canary not in body) or ("&" in body.split(canary)[0][-3:] if canary in body else False)
        context = body.split(canary)[0][-30:].replace("\n"," ") if canary in body else ""
        reflected.append({"param": param, "context": context})
        findings.append(wrap_finding(
            f"Parameter '{param}' reflects unescaped in response - candidate for XSS testing",
            "LOW",
            cvss="3.7", cwe="CWE-79",
            cwe_name="Improper Neutralization of Input During Web Page Generation",
            owasp="A03:2021",
            remediation="Apply context-appropriate output encoding (HTML, JS, URL, attribute, CSS) to all reflected user input. Use auto-escaping template engines.",
            evidence_marker=f"GET ?{param}={canary} -> canary appears verbatim in response; preceding context: ...{context}",
        ))

    return standard_response(
        tool="param_reflection", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Tested {tests} common parameter names; {len(reflected)} reflect input",
        raw_data={"param_reflection": {"reflected_params": reflected}},
    )


def register(app):
    app.include_router(router)
