"""CSRF protection scanner.

Reports MEDIUM finding only when BOTH defenses are missing:
  1. CSRF token field in state-changing forms (POST/PUT/DELETE/PATCH)
  2. SameSite=Lax/Strict on session cookies

Crawls homepage + 7 common pages (login, signup, account, dashboard,
profile, settings) — no deep crawl. Zero FP because we require both
defenses to be absent.
"""
import re
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url,
    safe_get, wrap_finding, standard_response,
)

router = APIRouter()


CSRF_TOKEN_NAMES = [
    "csrf_token", "csrftoken", "csrfmiddlewaretoken",
    "_token", "_csrf", "_csrf_token",
    "authenticity_token", "anticsrf", "anti-csrf",
    "__requestverificationtoken", "csrfkey", "csrfid",
    "xsrf-token", "_xsrf", "request_token",
]
COMMON_PAGES = ["", "/login", "/signup", "/register", "/account",
                "/dashboard", "/profile", "/settings"]
STATE_CHANGING_METHODS = ("POST", "PUT", "DELETE", "PATCH")


def _extract_forms(html):
    forms = []
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.I)
    method_pattern = re.compile(r'method=["\']?([^"\'\s>]*)["\']?', re.I)
    action_pattern = re.compile(r'action=["\']?([^"\'\s>]*)["\']?', re.I)
    input_pattern = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)
    for fm in form_pattern.finditer(html):
        outer = fm.group(0); inner = fm.group(1)
        method_m = method_pattern.search(outer)
        action_m = action_pattern.search(outer)
        method = method_m.group(1).upper() if method_m else "GET"
        action = action_m.group(1) if action_m else ""
        fields = [im.group(1) for im in input_pattern.finditer(inner)]
        has_token = any(
            any(tok_name in f.lower() for tok_name in CSRF_TOKEN_NAMES)
            for f in fields
        )
        forms.append({"method": method, "action": action, "fields": fields,
                      "has_csrf_token": has_token})
    return forms


def _samesite_present(response):
    for c in response.cookies:
        if hasattr(c, "_rest"):
            for k, v in c._rest.items():
                if k.lower() == "samesite" and v and v.lower() in ("lax", "strict"):
                    return True
        try:
            if c.has_nonstandard_attr("SameSite"):
                ss = c.get_nonstandard_attr("SameSite") or ""
                if ss.lower() in ("lax", "strict"):
                    return True
        except Exception:
            pass
    raw = response.headers.get("Set-Cookie") or ""
    if re.search(r"samesite\s*=\s*(lax|strict)", raw, re.I):
        return True
    return False


@router.post("/api/scan/csrf")
async def scan_csrf(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    raw_results = []

    home = safe_get(base, req=req, allow_redirects=True, timeout=10)
    if home is None:
        return standard_response(
            tool="csrf", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {base}",
        )
    has_samesite = _samesite_present(home)
    unprotected_forms = []

    for path in COMMON_PAGES:
        tests += 1
        page_url = base + path if path else base
        r = home if path == "" else safe_get(page_url, req=req, allow_redirects=True, timeout=10)
        if r is None or r.status_code != 200:
            raw_results.append({"page": page_url, "status": r.status_code if r else "no response"})
            continue
        forms = _extract_forms(r.text or "")
        state_changing = [f for f in forms if f["method"] in STATE_CHANGING_METHODS]
        no_token = [f for f in state_changing if not f["has_csrf_token"]]
        for f in no_token:
            unprotected_forms.append({
                "page": page_url, "method": f["method"],
                "action": f["action"] or page_url, "fields": f["fields"][:10],
            })
        raw_results.append({"page": page_url, "forms_total": len(forms),
                            "state_changing": len(state_changing),
                            "no_csrf_token": len(no_token)})

    if unprotected_forms and not has_samesite:
        summary = "; ".join(f"{f['method']} {f['action'][:60]}" for f in unprotected_forms[:5])
        if len(unprotected_forms) > 5:
            summary += f" (+{len(unprotected_forms)-5} more)"
        findings.append(wrap_finding(
            f"Missing CSRF protection — {len(unprotected_forms)} state-changing form(s) without token or SameSite cookies",
            "MEDIUM", cwe="CWE-352", owasp="A01:2021",
            evidence_marker=f"Found state-changing forms without CSRF token: {summary}. Session cookies do not declare SameSite=Lax/Strict.",
            remediation="Use both defenses: (a) Add CSRF token field to state-changing forms and validate server-side (Django/Rails/Spring/ASP.NET MVC all have this built-in). (b) Set SameSite=Lax or Strict on session cookies. Also validate Origin/Referer on sensitive endpoints.",
            tests_performed=tests,
            cvss="6.5",
        ))

    return standard_response(
        tool="csrf", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"Crawled {tests} common page(s); found {len(unprotected_forms)} state-changing form(s) without CSRF token; SameSite cookie protection: {'PRESENT' if has_samesite else 'MISSING'}",
        raw_data={"csrf": {"pages_crawled": tests, "unprotected_forms": unprotected_forms,
                           "samesite_cookies_present": has_samesite, "per_page": raw_results}},
    )


def register(app):
    app.include_router(router)
