"""Stored XSS — post a unique payload, GET listing endpoints, look for echoed-unescaped match."""
import secrets
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, safe_post, wrap_finding, standard_response)
from tools._spa_state import load_spa_state

router = APIRouter()

# (POST endpoint, JSON shape with __PAYLOAD__ placeholder, GET listing path)
_TARGETS = [
    ("/api/Feedbacks", {"comment": "__PAYLOAD__", "rating": 3, "captcha": "1", "captchaId": 1}, "/api/Feedbacks"),
    ("/api/feedbacks", {"comment": "__PAYLOAD__", "rating": 3}, "/api/feedbacks"),
    ("/api/comments",  {"text": "__PAYLOAD__"}, "/api/comments"),
    ("/api/Reviews",   {"review": "__PAYLOAD__", "rating": 3}, "/api/Reviews"),
    ("/api/posts",     {"title": "Test", "content": "__PAYLOAD__"}, "/api/posts"),
]


@router.post("/api/scan/stored_xss")
async def scan_stored_xss(req: ScanRequest, _=Depends(verify_scan_quota)):
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

    return standard_response(tool="stored_xss", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Stored XSS: probed {len(_TARGETS)} post/get endpoint pairs for cross-request payload echo",
        raw_data={"stored_xss": {"confirmed": confirmed}})


def register(app):
    app.include_router(router)
