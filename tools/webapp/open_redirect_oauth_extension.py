"""open_redirect_oauth_extension — open-redirect via OAuth redirect_uri / SSO logout.

Goes deeper than basic open_redirect by targeting OAuth-specific redirect
params: redirect_uri, returnUrl, returnTo, post_logout_redirect_uri,
state-tied URLs. These are commonly used for SSO logout flows + auth
callback, and weak validation lets attacker redirect victim to phishing
clone post-logout.
"""
from urllib.parse import urlencode, urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()

# OAuth/SSO-specific redirect parameters
PARAMS = ["redirect_uri", "redirectUri", "post_logout_redirect_uri",
           "returnUrl", "returnTo", "ReturnUrl", "callback_url",
           "continue", "next", "redirect", "url"]

# Paths to test
PATHS = [
    "/logout", "/auth/logout", "/api/auth/logout",
    "/sso/logout", "/.auth/logout",
    "/login", "/auth/login", "/oauth/authorize",
]

# Open-redirect targets (attacker-controlled URLs)
EVIL_TARGETS = [
    "https://evil-attacker.example/phish",
    "//evil-attacker.example",
    "/\\evil-attacker.example",   # backslash trick
    "https:evil-attacker.example",  # missing slashes
]


def _probe(url, params, req):
    return safe_request("GET", url, params=params,
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)


@router.post("/api/webapp/scan/open_redirect_oauth_extension")
def scan_open_redirect_oauth_extension(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    base_host = urlparse(base).hostname or ""

    open_redirects = []
    tested_endpoints = 0
    for path in PATHS:
        # Baseline: hit without params, see if endpoint exists
        r0 = _probe(base + path, {}, req)
        if r0 is None or r0.status_code == 404: continue
        tested_endpoints += 1

        for param in PARAMS:
            for evil in EVIL_TARGETS:
                r = _probe(base + path, {param: evil}, req)
                if r is None: continue
                # Indicator: 3xx with Location pointing to evil-attacker.example
                loc = r.headers.get("location") or ""
                if r.status_code in (301, 302, 303, 307, 308):
                    loc_low = loc.lower()
                    if "evil-attacker.example" in loc_low or "evil-attacker" in loc_low:
                        open_redirects.append({
                            "path": path, "param": param,
                            "payload": evil, "redirect_to": loc[:120],
                            "status": r.status_code,
                        })
                        break  # one finding per param is enough
            if any(o["path"] == path and o["param"] == param for o in open_redirects):
                continue  # already flagged this path+param

    findings = []
    if open_redirects:
        findings.append(wrap_finding(
            f"OAuth-extension OPEN REDIRECT at {len(open_redirects)} location(s)",
            "HIGH", cvss="6.1", cwe="CWE-601", owasp="A01:2021",
            remediation="Validate redirect_uri / returnUrl / post_logout_redirect_uri "
                        "against an allow-list. NEVER let user-controlled URL drive "
                        "302. For OAuth: redirect_uri MUST exact-match registered "
                        "URI (no scheme/host/path flexibility). For SSO logout: "
                        "verify post_logout_redirect_uri is in OIDC client config. "
                        "Phishing pretexts often start from your-trusted-domain.com/"
                        "logout?returnTo=evil.com.",
            evidence_marker=" | ".join(
                f"{o['path']}?{o['param']}={o['payload']} → "
                f"{o['status']} {o['redirect_to']}"
                for o in open_redirects[:3]
            )))
    elif tested_endpoints > 0:
        findings.append(wrap_finding(
            f"OAuth-extension open-redirect rejected at {tested_endpoints} endpoint(s)",
            "POSITIVE", cwe="CWE-601",
            remediation="Maintain allow-list. Audit when adding new OAuth clients.",
            evidence_marker=f"{tested_endpoints} endpoints × {len(PARAMS)} params × "
                              f"{len(EVIL_TARGETS)} payloads all rejected"))
    else:
        return standard_response(
            tool="open_redirect_oauth_extension", target=req.target, findings=[],
            tests_performed=len(PATHS), vulnerable=False,
            skipped_reason="No common login/logout paths found")

    return standard_response(
        tool="open_redirect_oauth_extension", target=req.target, findings=findings,
        tests_performed=len(PATHS) * len(PARAMS) * len(EVIL_TARGETS),
        vulnerable=bool(open_redirects),
        tests_summary=f"{tested_endpoints} endpoints tested, {len(open_redirects)} vulnerable",
        raw_data={"open_redirects": open_redirects,
                   "tested_endpoints": tested_endpoints})


def register(app):
    app.include_router(router)
