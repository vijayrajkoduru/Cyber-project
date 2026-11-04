"""CSRF — passive form + cookie SameSite analysis.

VL-VERIFY: probes 8 common pages for state-changing forms. On an SPA, every
probed path returns the same index.html shell - if that shell happens to
contain a <form method="post"> template (login modal, contact form), the
scanner would repeat the same CSRF finding 8x. Canary check skips any path
whose response is byte-identical to a bogus-path probe.
"""
import re
import time
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding)
from tools.webapp._webapp_common import vuln_response, precheck_target
from tools._spa_state import load_spa_state
from tools._vl_core.spa_canary import detect_spa_catchall_sync, is_same_as_canary
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify
router = APIRouter()
_TOKEN_RE = re.compile(r"(csrf|csrftoken|_token|authenticity_token|xsrf|nonce|state)", re.IGNORECASE)
_PAGES = ["/", "/login", "/signin", "/register", "/signup", "/profile", "/settings", "/account"]
_FORM_RE = re.compile(r'<form[^>]*?(?:method=["\']?(\w+)["\']?)?[^>]*?>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_HIDDEN_RE = re.compile(r'<input[^>]*?type=["\']hidden["\'][^>]*?name=["\']([^"\']+)["\'][^>]*?>', re.IGNORECASE)

def _form_has_token(html):
    for name in _HIDDEN_RE.findall(html):
        if _TOKEN_RE.search(name): return True, name
    return False, None

@router.post("/api/webapp/scan/csrf")
@vl_turbo()
@vl_verify()
def scan_csrf(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    unreachable = precheck_target(base, req, active_probes=False)  # token-field inspection only — no payload injection
    if unreachable:
        return vuln_response(tool="csrf", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)
    findings, tests, forms_seen = [], 0, []
    samesite = "unknown"
    # VL-TURBO wall-clock cap: 9 calls × 10s × 3 retries = up to 4.5 min worst case.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 30.0
    _bailed = False
    # VL-VERIFY: fire canary once so we can recognize SPA catch-all paths
    spa = detect_spa_catchall_sync(base)
    spa_suppressed = []
    r0 = safe_get(base, req=req, allow_redirects=True, timeout=8, retries=0)
    if r0 is not None:
        for c in r0.cookies:
            if hasattr(c, "_rest"):
                for k, v in c._rest.items():
                    if k.lower() == "samesite": samesite = v.lower(); break
    # VL-TURBO deep: parallelize the 8-page fetch across pool(8).
    # Was 8 sequential GETs * 8s = ~64s. Now ~8s in parallel.
    def _fetch_page(path):
        r = safe_get(base + path, req=req, allow_redirects=True,
                      timeout=8, retries=0)
        return (path, r)

    try:
        with ThreadPoolExecutor(max_workers=min(8, len(_PAGES))) as pool:
            page_results = list(pool.map(_fetch_page, _PAGES,
                                          timeout=_WALLCLOCK_BUDGET))
    except TimeoutError:
        _bailed = True
        page_results = []

    for path, r in page_results:
        tests += 1
        if r is None or r.status_code != 200:
            continue
        if spa["is_spa"] and is_same_as_canary(r.text or "", spa["canary_body"]):
            spa_suppressed.append(path)
            continue
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
    # POST-FORM-CSRF-V1 — the page list above misses deep state-changing forms
    # (e.g. DVWA /vulnerabilities/csrf/ password change). For each discovered/
    # seeded form, fetch its action page and flag it if NO anti-CSRF token is
    # present. Seeded forms are known state-changing, so GET-method ones count
    # too (a state-changing GET with no token is strictly worse).
    _already = {f.get("page") for f in forms_seen}
    for form in [f for f in (load_spa_state(req.target).get("forms") or [])
                 if f.get("type") == "csrf"][:6]:
        action = form.get("action")
        if not action or action in _already:
            continue
        tests += 1
        r = safe_get(action, req=req, allow_redirects=True, timeout=8, retries=0)
        if r is None or r.status_code != 200:
            continue
        html = r.text or ""
        page_has_token = any(_form_has_token(fh)[0] for _m, fh in _FORM_RE.findall(html)[:5])
        forms_seen.append({"page": action, "method": str(form.get("method", "")).upper(),
                           "has_token": page_has_token, "token_name": None})
        if not page_has_token and samesite in ("", "none", "unknown"):
            findings.append(wrap_finding(
                f"CSRF protection missing on state-changing form at {action}",
                "MEDIUM", cvss="6.5", cwe="CWE-352", owasp="A01:2021",
                remediation="Add a per-request CSRF token to state-changing forms. Use framework CSRF middleware. Set SameSite=Lax on session cookies.",
                evidence_marker=f"form at {action} has no anti-CSRF token AND SameSite={samesite}"))
    summary = f"CSRF: crawled {tests} pages, analysed {len(forms_seen)} state-changing forms in {time.time() - _wallclock_start:.1f}s"
    if _bailed:
        summary += f" — VL-TURBO wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    if spa_suppressed:
        summary += f"; {len(spa_suppressed)} SPA-shell path(s) skipped"
    return vuln_response(tool="csrf", target=req.target, findings=findings,
        tested=max(tests, 1),
        what_checked="state-changing forms for missing CSRF tokens + cookie SameSite",
        tests_summary=summary,
        raw_data={"csrf": {"forms_seen": forms_seen, "samesite_status": samesite,
                            "wallclock_bailed": _bailed,
                            "spa_catchall": spa["is_spa"],
                            "spa_suppressed_paths": spa_suppressed}})
def register(app): app.include_router(router)
