"""Stored XSS — post a unique payload, GET listing endpoints, look for echoed-unescaped match."""
import secrets
from urllib.parse import urlencode
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, safe_post, wrap_finding, standard_response)
from tools._shared import destructive_skip
from tools._spa_state import load_spa_state
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
    # (e.g. DVWA guestbook /vulnerabilities/xss_s/), not just JSON APIs. For each
    # discovered/seeded form, submit a unique <script> marker into its text
    # fields, then re-fetch the form page; if the marker comes back UNESCAPED,
    # it is stored XSS.
    spa = load_spa_state(req.target)
    for form in [f for f in (spa.get("forms") or []) if f.get("text_fields")][:6]:
        action = form.get("action")
        tfields = [f for f in (form.get("text_fields") or []) if f]
        if not action or not tfields:
            continue
        method = str(form.get("method", "post")).lower()
        marker = "vlsx" + secrets.token_hex(5)
        payload = f"<script>{marker}</script>"
        data = {f: "vltest" for f in tfields}
        data.update(dict(form.get("extra") or {}))
        data[tfields[-1]] = payload   # payload into the message-like field
        tests += 1
        if method == "post":
            safe_post(action, data=data, req=req, allow_redirects=True, timeout=10)
        else:
            sep = "&" if "?" in action else "?"
            safe_get(action + sep + urlencode(data), req=req, allow_redirects=True, timeout=10)
        tests += 1
        g = safe_get(action, req=req, allow_redirects=True, timeout=10)
        body = (g.text if g is not None else "") or ""
        if payload in body:   # verbatim, unescaped
            findings.append(wrap_finding(
                f"Stored XSS — payload submitted to {action} echoed unescaped on reload",
                "CRITICAL", cvss="9.6", cwe="CWE-79", owasp="A03:2021",
                remediation=("HTML-escape user content on output. Sanitise stored content "
                           "(DOMPurify/bleach). Add a strict Content-Security-Policy."),
                evidence_marker=f"{method.upper()} {action} field={tfields[-1]!r} marker {marker} reflected verbatim on reload"))
            confirmed.append({"action": action, "field": tfields[-1], "marker": marker})
            break

    return standard_response(tool="stored_xss", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Stored XSS: probed {len(_TARGETS)} post/get endpoint pairs for cross-request payload echo",
        raw_data={"stored_xss": {"confirmed": confirmed}})


def register(app):
    app.include_router(router)
