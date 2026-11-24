"""Stored XSS — post a unique payload, GET listing endpoints, look for echoed-unescaped match."""
import secrets
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, safe_post, wrap_finding, standard_response)
from tools._shared import destructive_skip
from tools._spa_state import load_spa_state
from tools.webapp import _post_forms as pf
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

# (POST endpoint, JSON shape with __PAYLOAD__ placeholder, GET listing path)
_TARGETS = [
    ("/api/Feedbacks", {"comment": "__PAYLOAD__", "rating": 3, "captcha": "1", "captchaId": 1}, "/api/Feedbacks"),
    ("/api/feedbacks", {"comment": "__PAYLOAD__", "rating": 3}, "/api/feedbacks"),
    ("/api/comments",  {"text": "__PAYLOAD__"}, "/api/comments"),
    ("/api/Reviews",   {"review": "__PAYLOAD__", "rating": 3}, "/api/Reviews"),
    ("/api/posts",     {"title": "Test", "content": "__PAYLOAD__"}, "/api/posts"),
]


def _juice_captcha(base, req):
    """Juice Shop issues a fresh captcha per feedback POST (a per-request
    token in all but name); the hard-coded captchaId/captcha pair was always
    rejected. Fetch a fresh one right before each submit."""
    r = safe_get(base + "/rest/captcha/", req=req, allow_redirects=False, timeout=8, retries=0)
    try:
        j = r.json() if r is not None and r.status_code == 200 else None
        if isinstance(j, dict) and "captchaId" in j and "answer" in j:
            return {"captchaId": j["captchaId"], "captcha": str(j["answer"])}
    except Exception:
        pass
    return {}


@router.post("/api/webapp/scan/stored_xss")
@vl_turbo()
@vl_verify()
def scan_stored_xss(req: ScanRequest, _=Depends(verify_scan_quota)):
    # SAFETY-POLICY-V1: CUSTOMER-mode profiles with destructive tests
    # disabled get a SKIPPED result (LAB mode: always allowed).
    _vl_skip = destructive_skip(req, "stored_xss")
    if _vl_skip:
        return _vl_skip
    base = web_url(req.target).rstrip("/")
    findings, tests, confirmed = [], 0, []

    for post_path, body_template, get_path in _TARGETS:
        marker = "vlxs" + secrets.token_hex(5)
        payload = f'<svg/onload="{marker}=1">'
        body = {k: (v.replace("__PAYLOAD__", payload) if isinstance(v, str) else v)
                for k, v in body_template.items()}
        if "captchaId" in body:
            body.update(_juice_captcha(base, req))

        tests += 1
        post_r = safe_post(base + post_path, json=body, req=req,
                            headers={"Content-Type": "application/json"},
                            allow_redirects=False, timeout=10)
        if post_r is None or post_r.status_code not in (200, 201):
            continue

        # GET the listing back — payload should appear in response IF stored unescaped
        tests += 1
        get_r = safe_get(base + get_path, req=req, allow_redirects=False, timeout=10)
        if get_r is None or get_r.status_code != 200:
            continue
        if payload in (get_r.text or "") and "&lt;svg" not in (get_r.text or ""):
            # Verbatim payload echo without HTML-escape = stored XSS
            findings.append(wrap_finding(
                f"Stored XSS — payload posted to {post_path} echoed unescaped at {get_path}",
                "CRITICAL", cvss="9.6", cwe="CWE-79", owasp="A03:2021",
                remediation=("Apply HTML-escape on the OUTPUT side (when rendering user content). "
                           "Sanitise stored content with a library like DOMPurify/bleach. "
                           "Set strict Content-Security-Policy as defense-in-depth."),
                evidence_marker=f"POST {post_path} → marker stored → GET {get_path} echoed payload verbatim"))
            confirmed.append({"post": post_path, "get": get_path, "marker": marker})
            break  # one is enough

    # POST-FORM-STORED-XSS-V1 — classic stored XSS lives behind HTML POST forms
    # (e.g. DVWA guestbook /vulnerabilities/xss_s/), not just JSON APIs.
    # STORED-XSS-CSRF-V1 — submissions go through the shared POST-form helper
    # (tools.webapp._post_forms), which re-fetches the form page right before
    # EVERY submit and re-scrapes the hidden anti-CSRF fields (DVWA user_token,
    # Django csrfmiddlewaretoken, Rails authenticity_token, ...). The previous
    # hand-rolled loop posted the crawl-time token (or none at all), so on
    # per-request-token forms every payload was rejected -> false negative.
    # One field is injected per submission (others keep benign defaults); a
    # fresh, payload-free GET of the form page / action must return the unique
    # marker verbatim for a finding (a reflection in the POST response itself
    # does not count). Sensitive forms (login, password, reset/clear) are
    # dropped by normalized_post_forms.
    spa = load_spa_state(req.target)
    form_hit = False
    for form in pf.normalized_post_forms(spa, limit=6):
        if form_hit:
            break
        for field in list(form["injectable"])[:4]:
            marker = "vlsx" + secrets.token_hex(5)
            payload = f'<svg/onload="{marker}=1">'
            tests += 1
            resp = pf.submit(form, req, field, payload, timeout=10)
            if resp is None or resp.status_code >= 400:
                continue
            hit_view = None
            for view in dict.fromkeys([form["page"], form["action"]]):
                tests += 1
                g = safe_get(view, req=req, allow_redirects=True, timeout=10)
                if g is not None and g.status_code == 200 and payload in (g.text or ""):
                    hit_view = view
                    break
            if hit_view:
                findings.append(wrap_finding(
                    f"Stored XSS — field {field!r} submitted to {form['action']} rendered unescaped on reload",
                    "CRITICAL", cvss="9.6", cwe="CWE-79", owasp="A03:2021",
                    remediation=("HTML-escape user content on output. Sanitise stored content "
                               "(DOMPurify/bleach). Add a strict Content-Security-Policy."),
                    evidence_marker=(f"POST {form['action']} field={field!r} marker {marker} "
                                     f"(CSRF fields refreshed: {form.get('csrf_fields') or 'none'}) "
                                     f"-> fresh GET {hit_view} returned payload verbatim")))
                confirmed.append({"action": form["action"], "field": field,
                                  "get": hit_view, "marker": marker})
                form_hit = True
                break

    return standard_response(tool="stored_xss", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Stored XSS: probed {len(_TARGETS)} post/get endpoint pairs for cross-request payload echo",
        raw_data={"stored_xss": {"confirmed": confirmed}})


def register(app):
    app.include_router(router)
