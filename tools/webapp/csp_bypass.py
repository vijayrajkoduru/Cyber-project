"""Webapp: CSP weakness detection (unsafe-inline, unsafe-eval, * wildcards, JSONP hosts)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response

router = APIRouter()

_JSONP_HOSTS = ["www.googleapis.com","ajax.googleapis.com","apis.google.com","accounts.google.com","plus.google.com","www.youtube.com","s.ytimg.com","cdnjs.cloudflare.com","ajax.aspnetcdn.com","code.jquery.com","stackpath.bootstrapcdn.com"]


def _parse_csp(csp_header):
    parts = {}
    for chunk in csp_header.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        bits = chunk.split(None, 1)
        directive = bits[0].lower()
        sources = bits[1].split() if len(bits) > 1 else []
        parts[directive] = sources
    return parts


@router.post("/api/webapp/csp_bypass")
async def webapp_csp_bypass(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 1
    
    r = safe_get(base + "/", req=req, allow_redirects=True, timeout=8)
    if r is None:
        return standard_response(tool="csp_bypass", target=req.target, findings=[],
                                 tests_performed=tests, skipped_reason="Could not reach target")
    csp = r.headers.get("Content-Security-Policy") or r.headers.get("Content-Security-Policy-Report-Only")
    if not csp:
        return standard_response(tool="csp_bypass", target=req.target, findings=[],
                                 tests_performed=tests,
                                 skipped_reason="No Content-Security-Policy header (covered by security_headers scanner)")
    
    parts = _parse_csp(csp)
    script_src = parts.get("script-src", parts.get("default-src", []))
    weaknesses = []
    
    # 1. unsafe-inline in script-src
    if "'unsafe-inline'" in script_src:
        weaknesses.append("unsafe-inline")
        findings.append(wrap_finding(
            "CSP allows 'unsafe-inline' in script-src - inline scripts and event handlers permitted",
            "HIGH",
            cvss="7.5", cwe="CWE-1173",
            cwe_name="Improper Use of Validation Framework",
            owasp="A05:2021",
            remediation="Remove 'unsafe-inline'. Migrate to nonce-based CSP: script-src 'nonce-{random}' or hash-based.",
            evidence_marker=f"CSP script-src: {' '.join(script_src)}",
        ))
    
    # 2. unsafe-eval
    if "'unsafe-eval'" in script_src:
        weaknesses.append("unsafe-eval")
        findings.append(wrap_finding(
            "CSP allows 'unsafe-eval' - eval()/Function() execution permitted",
            "MEDIUM",
            cvss="6.5", cwe="CWE-95",
            cwe_name="Improper Neutralization of Directives in Dynamically Evaluated Code",
            owasp="A03:2021",
            remediation="Remove 'unsafe-eval'. Refactor code to avoid eval() / new Function() / setTimeout(string).",
            evidence_marker=f"CSP script-src includes 'unsafe-eval': {' '.join(script_src)}",
        ))
    
    # 3. Wildcard * in script-src or default-src
    if "*" in script_src or "https:" in script_src or "data:" in script_src:
        weaknesses.append("wildcard/data:")
        findings.append(wrap_finding(
            f"CSP script-src allows broad sources: {[s for s in script_src if s in ('*','https:','data:')]}",
            "HIGH",
            cvss="7.5", cwe="CWE-1173",
            owasp="A05:2021",
            remediation="Replace * / https: / data: in script-src with specific trusted hosts.",
            evidence_marker=f"CSP: {csp[:200]}",
        ))
    
    # 4. JSONP-capable hosts (XSS gadget)
    for jh in _JSONP_HOSTS:
        if jh in csp:
            weaknesses.append(f"jsonp:{jh}")
            findings.append(wrap_finding(
                f"CSP whitelists {jh} - JSONP endpoint enables CSP bypass",
                "MEDIUM",
                cvss="6.1", cwe="CWE-1173",
                owasp="A05:2021",
                remediation=f"Remove {jh} from script-src unless absolutely needed. Many big-CDN hosts expose JSONP endpoints that bypass CSP.",
                evidence_marker=f"CSP includes {jh}",
            ))

    return standard_response(
        tool="csp_bypass", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Parsed CSP header; found {len(weaknesses)} weakness(es)",
        raw_data={"csp_bypass": {"csp": csp, "weaknesses": weaknesses, "script_src": script_src}},
    )


def register(app):
    app.include_router(router)
