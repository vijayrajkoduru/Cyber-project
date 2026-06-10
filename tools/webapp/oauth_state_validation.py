"""oauth_state_validation — OAuth callback state-parameter validation check.

OAuth2 RFC requires `state` parameter to prevent CSRF on the redirect URI.
Tests whether the app's OAuth callback accepts a missing or modified state.

Probes common OAuth callback paths with crafted query strings; success
criteria: callback returns 200/302 to logged-in state WITHOUT a valid
state cookie/session, OR doesn't return error.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

CALLBACK_PATHS = [
    "/oauth/callback", "/auth/callback", "/oauth2/callback",
    "/auth/google/callback", "/auth/facebook/callback",
    "/auth/github/callback", "/login/callback",
    "/api/auth/callback/google", "/api/auth/callback/github",
    "/.auth/login/aad/callback", "/signin-oidc",
]


def _probe(url, params, req):
    return safe_request("GET", url, params=params,
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=10, allow_redirects=False)


@router.post("/api/webapp/scan/oauth_state_validation")
@vl_turbo()
def scan_oauth_state_validation(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    found_callbacks = []
    no_state_accepted = []

    for path in CALLBACK_PATHS:
        url = base + path
        # First: probe without any params — does this look like a callback?
        r0 = _probe(url, {}, req)
        if r0 is None: continue
        # If 404, skip
        if r0.status_code == 404: continue

        # Callback path appears to exist
        found_callbacks.append(path)

        # Probe 1: missing state
        r1 = _probe(url, {"code": "vulnuslab-test-code-12345"}, req)
        # Probe 2: modified state
        r2 = _probe(url, {"code": "vulnuslab-test-code-12345",
                            "state": "attacker-fixated-state"}, req)

        # Indicator of vuln: 200/302 WITHOUT explicit state-validation error
        for label, r in (("no-state", r1), ("attacker-state", r2)):
            if r is None: continue
            body = (r.text or "")[:5000].lower()
            err_words = ("invalid state", "state mismatch", "csrf",
                          "missing state", "state parameter",
                          "invalid_state", "no state")
            has_err = any(w in body for w in err_words)
            # 302 to login error / unsafe redirect to homepage is what we're flagging
            if r.status_code in (200, 302) and not has_err:
                # Specifically suspicious if location is NOT explicit error
                loc = r.headers.get("location", "")
                if "error" not in loc.lower() and "invalid" not in loc.lower():
                    no_state_accepted.append({
                        "path": path, "probe": label,
                        "status": r.status_code, "location": loc[:120]
                    })
                    break  # one finding per path is enough

    findings = []
    if no_state_accepted:
        findings.append(wrap_finding(
            f"OAuth callback(s) accept missing/forged state ({len(no_state_accepted)})",
            "HIGH", cvss="8.1", cwe="CWE-352", owasp="A01:2021",
            remediation="OAuth2 spec REQUIRES state validation: (1) Generate "
                        "cryptographically random state per auth-flow start, store "
                        "in session cookie. (2) On callback, COMPARE incoming state "
                        "vs session state. Reject if missing or mismatched with "
                        "explicit 400 error. (3) Without this, attacker can fixate "
                        "their own auth code on victim's session → account takeover. "
                        "Reference: RFC 6749 §10.12.",
            evidence_marker=" | ".join(
                f"{e['path']} ({e['probe']}): HTTP {e['status']} loc={e['location']}"
                for e in no_state_accepted[:3]
            )))
    elif found_callbacks:
        findings.append(wrap_finding(
            f"OAuth callback(s) ({len(found_callbacks)}) appear to validate state",
            "POSITIVE", cwe="CWE-352",
            remediation="Maintain state validation. Add nonce verification too for "
                        "OIDC flows.",
            evidence_marker=f"paths: {', '.join(found_callbacks[:5])}"))

    if not found_callbacks:
        return standard_response(
            tool="oauth_state_validation", target=req.target, findings=[],
            tests_performed=len(CALLBACK_PATHS), vulnerable=False,
            skipped_reason="No OAuth callback paths found at common locations")

    return standard_response(
        tool="oauth_state_validation", target=req.target, findings=findings,
        tests_performed=len(CALLBACK_PATHS), vulnerable=bool(no_state_accepted),
        tests_summary=f"{len(found_callbacks)} callbacks; {len(no_state_accepted)} accept no-state",
        raw_data={"callbacks_found": found_callbacks,
                   "no_state_accepted": no_state_accepted})


def register(app):
    app.include_router(router)
