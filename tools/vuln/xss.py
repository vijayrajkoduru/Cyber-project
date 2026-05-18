"""Reflected XSS scanner — canary-based detection."""
import re, secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
router = APIRouter()

def _extract_param_urls(base_url, html):
    urls = set()
    parsed = urlparse(base_url)
    if parsed.query: urls.add(base_url)
    for m in re.finditer(r'href=["\']([^"\']*\?[^"\']+)["\']', html or "", re.I):
        href = m.group(1)
        if href.startswith("http"): urls.add(href)
        elif href.startswith("/"): urls.add(f"{parsed.scheme}://{parsed.netloc}{href}")
    for action in re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html or "", re.I):
        if action.startswith("http"): urls.add(action)
        elif action.startswith("/"): urls.add(f"{parsed.scheme}://{parsed.netloc}{action}")
    return list(urls)[:10]

def _reflection_context(canary, body):
    if not body or canary not in body: return None
    idx = body.find(canary)
    if "<script" in body[max(0, idx-300):idx]: return "js"
    if re.search(r'=["\'][^"\']*$', body[:idx]): return "attribute"
    return "html"

@router.post("/api/scan/xss")
async def scan_xss(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    r = safe_get(base, req=req, allow_redirects=True)
    if r is None:
        return standard_response(tool="xss", target=req.target, findings=[],
            tests_performed=1, vulnerable=False, skipped_reason=f"Could not reach {base}")
    urls = _extract_param_urls(base, r.text or "")

    # Augment with SPA-discovered URLs that have query params
    spa = load_spa_state(req.target)
    for spa_url in spa.get("urls", []):
        if "?" in spa_url and spa_url not in urls:
            urls.append(spa_url)

    if not urls:
        return standard_response(tool="xss", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters or form inputs found to test")
    findings, tests = [], 0
    for u in urls:
        parsed = urlparse(u)
        params = parse_qs(parsed.query)
        if not params: continue
        for key in list(params.keys())[:5]:
            tests += 1
            canary = "v" + secrets.token_hex(6) + "x"
            new_params = {k: v[0] for k, v in params.items()}
            new_params[key] = canary
            test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
            r2 = safe_get(test_url, req=req, allow_redirects=True, timeout=10)
            if r2 is None: continue
            ctx = _reflection_context(canary, r2.text or "")
            if not ctx: continue
            sev = {"js":"CRITICAL","attribute":"HIGH","html":"HIGH"}[ctx]
            cvss = {"js":"9.0","attribute":"7.5","html":"7.5"}[ctx]
            findings.append(wrap_finding(
                f"Reflected XSS — parameter {key!r} reflects unescaped in {ctx} context",
                sev, cvss=cvss, cwe="CWE-79", owasp="A03:2021",
                remediation="Context-aware output encoding (HTML/JS/URL). Use auto-escaping templates.",
                evidence_marker=f"canary={canary} appeared unescaped in {ctx} context"))
            break
    return standard_response(tool="xss", target=req.target, findings=findings,
        tests_performed=max(tests, 1),
        tests_summary=f"Tested {tests} params across {len(urls)} URLs with unique canaries",
        raw_data={"xss": {"urls_tested": urls, "tests": tests}})
def register(app): app.include_router(router)
