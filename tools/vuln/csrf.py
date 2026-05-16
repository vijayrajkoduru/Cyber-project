"""CSRF — passive form + cookie SameSite analysis."""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
router = APIRouter()
_TOKEN_RE = re.compile(r"(csrf|csrftoken|_token|authenticity_token|xsrf|nonce|state)", re.IGNORECASE)
_PAGES = ["/", "/login", "/signin", "/register", "/signup", "/profile", "/settings", "/account"]
_FORM_RE = re.compile(r'<form[^>]*?(?:method=["\']?(\w+)["\']?)?[^>]*?>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_HIDDEN_RE = re.compile(r'<input[^>]*?type=["\']hidden["\'][^>]*?name=["\']([^"\']+)["\'][^>]*?>', re.IGNORECASE)

def _form_has_token(html):
    for name in _HIDDEN_RE.findall(html):
        if _TOKEN_RE.search(name): return True, name
    return False, None

@router.post("/api/scan/csrf")
async def scan_csrf(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings, tests, forms_seen = [], 0, []
    samesite = "unknown"
    r0 = safe_get(base, req=req, allow_redirects=True, timeout=10)
    if r0 is not None:
        for c in r0.cookies:
            if hasattr(c, "_rest"):
                for k, v in c._rest.items():
                    if k.lower() == "samesite": samesite = v.lower(); break
    for path in _PAGES:
        tests += 1
        r = safe_get(base + path, req=req, allow_redirects=True, timeout=10)
        if r is None or r.status_code != 200: continue
        for method, form_html in _FORM_RE.findall(r.text or "")[:5]:
            method = (method or "GET").upper()
            if method == "GET": continue
            has_token, token_name = _form_has_token(form_html)
            forms_seen.append({"page": path, "method": method, "has_token": has_token, "token_name": token_name})
            if not has_token and samesite in ("", "none", "unknown"):
                findings.append(wrap_finding(
                    f"CSRF protection missing on {method} form at {path}",
                    "MEDIUM", cvss="6.5", cwe="CWE-352", owasp="A01:2021",
                    remediation="Add CSRF token to state-changing forms. Use framework CSRF middleware (Django/Rails/Express csurf). Set SameSite=Lax on session cookies.",
                    evidence_marker=f"{method} form at {path} has no CSRF token AND SameSite={samesite}"))
    return standard_response(tool="csrf", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"CSRF: crawled {tests} pages, analysed {len(forms_seen)} state-changing forms",
        raw_data={"csrf": {"forms_seen": forms_seen, "samesite_status": samesite}})
def register(app): app.include_router(router)
