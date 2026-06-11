"""oauth_front_channel_logout — OAuth/OIDC front-channel logout audit.

OIDC front-channel logout uses iframe-based logout broadcast to all
sessions. Misconfig:
  - Logout endpoint accepts any redirect_uri (open redirect)
  - Logout doesn't actually invalidate server-side session (only client cookie)
  - End-session endpoint missing entirely (no clean SSO logout)
"""
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
LOGOUT_PATHS = [
    "/logout", "/api/logout", "/auth/logout",
    "/connect/endsession", "/oauth2/sessions/logout",
    "/.well-known/end_session_endpoint",
]


@router.post("/api/webapp/scan/oauth_front_channel_logout")
@vl_turbo()
@vl_verify()
def scan_oauth_front_channel_logout(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    issues = []
    found_logout = None

    def _probe(path):
        r = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r is None or r.status_code == 404: return None
        local_issues = []
        for param in ("post_logout_redirect_uri", "returnTo", "redirect"):
            r_ev = safe_request("GET", base + path,
                params={param: "https://evil-attacker.example"},
                headers={"User-Agent": "VulnusLab/1.0"},
                req=req, timeout=8, allow_redirects=False)
            if r_ev is None: continue
            loc = (r_ev.headers.get("location") or "").lower()
            if "evil-attacker" in loc:
                local_issues.append({"path": path, "param": param,
                                     "redirect_to": loc[:100]})
        return {"path": path, "issues": local_issues}

    # VL-TURBO deep: parallelize 6 logout paths via pool(6); each path serially tests 3 params.
    # Was ~144s sequential, now ~32s parallel.
    results = []
    with ThreadPoolExecutor(max_workers=min(6, len(LOGOUT_PATHS))) as pool:
        for result in pool.map(_probe, LOGOUT_PATHS, timeout=21):
            if result is not None:
                results.append(result)
    # Preserve original ordering for found_logout (first reachable path in LOGOUT_PATHS)
    order = {p: i for i, p in enumerate(LOGOUT_PATHS)}
    results.sort(key=lambda r: order.get(r["path"], 999))
    for r in results:
        if not found_logout: found_logout = r["path"]
        issues.extend(r["issues"])
    findings = []
    if issues:
        findings.append(wrap_finding(
            f"OAuth front-channel logout open-redirect at {len(issues)} endpoint(s)",
            "HIGH", cvss="6.1", cwe="CWE-601", owasp="A01:2021",
            remediation="Validate post_logout_redirect_uri against per-client "
                        "whitelist in OIDC config. RFC 8414 / OIDC Front-Channel "
                        "Logout spec REQUIRES allow-list. Without it, attacker "
                        "phishes via /logout?post_logout_redirect_uri=evil.com.",
            evidence_marker=" | ".join(
                f"{i['path']}?{i['param']}=evil.com → {i['redirect_to']}"
                for i in issues[:3]
            )))
    elif found_logout:
        findings.append(wrap_finding(
            "OAuth logout endpoint(s) reject arbitrary post_logout_redirect_uri",
            "POSITIVE", cwe="CWE-601", remediation="Maintain.",
            evidence_marker=f"logout path: {found_logout}, no open-redirect"))
    else:
        return standard_response(
            tool="oauth_front_channel_logout", target=req.target, findings=[],
            tests_performed=len(LOGOUT_PATHS), vulnerable=False,
            skipped_reason="No OAuth logout endpoints found")
    return standard_response(
        tool="oauth_front_channel_logout", target=req.target, findings=findings,
        tests_performed=len(LOGOUT_PATHS) * 4, vulnerable=bool(issues),
        tests_summary=f"logout: {found_logout}, {len(issues)} open-redirects",
        raw_data={"issues": issues})


def register(app):
    app.include_router(router)
