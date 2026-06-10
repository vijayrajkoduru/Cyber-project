"""Webapp: OAuth redirect_uri / state tampering detection."""
import re
import secrets
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync

router = APIRouter()

_OAUTH_PATHS = ["/oauth/authorize","/oauth2/authorize","/auth/oauth/authorize","/o/authorize","/login/oauth/authorize","/connect/authorize"]
_FALLBACK_BYPASS_VARIANTS = [
    "http://attacker.example/callback",
    "//attacker.example/callback",
    "/\\attacker.example/callback",
    "http://legitsite.com.attacker.example/cb",
]
# AI-curated 80-entry bypass list — extend variants
try:
    from tools._payloads.oauth_redirect_bypass_payloads import OAUTH_REDIRECT_BYPASS_PAYLOADS as _AI_OAUTH
    _BYPASS_VARIANTS = list(_FALLBACK_BYPASS_VARIANTS)
    seen = set(_BYPASS_VARIANTS)
    for _p in _AI_OAUTH:
        if not isinstance(_p, dict): continue
        payload = _p.get("payload", "")
        if payload and payload not in seen:
            _BYPASS_VARIANTS.append(payload)
            seen.add(payload)
    _BYPASS_VARIANTS = _BYPASS_VARIANTS[:25]  # cap for runtime
except Exception:
    _BYPASS_VARIANTS = _FALLBACK_BYPASS_VARIANTS


@router.post("/api/webapp/oauth_redirect_bypass")
async def webapp_oauth_redirect_bypass(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []
    tests = 0
    suspect = []
    # Find an OAuth endpoint
    oauth_url = None
    for p in _OAUTH_PATHS:
        tests += 1
        r = safe_get(base + p, req=req, allow_redirects=False, timeout=6)
        if r is None or r.status_code == 404:
            continue
        oauth_url = base + p
        break
    if not oauth_url:
        return standard_response(
            tool="oauth_redirect_bypass", target=req.target, findings=[],
            tests_performed=tests, skipped_reason="No OAuth /authorize endpoint discovered",
        )
    
    state = secrets.token_hex(8)
    for variant in _BYPASS_VARIANTS:
        tests += 1
        url = f"{oauth_url}?response_type=code&client_id=test&redirect_uri={variant}&state={state}"
        r = safe_get(url, req=req, allow_redirects=False, timeout=8)
        if r is None:
            continue
        loc = r.headers.get("Location","")
        # Bypass succeeds if 302/303 with Location pointing to attacker domain (no rejection)
        if r.status_code in (302, 303, 307) and ("attacker.example" in loc):
            suspect.append({"variant": variant, "location": loc[:120]})
            findings.append(wrap_finding(
                f"OAuth redirect_uri bypass - '{variant}' accepted, redirected to attacker domain",
                "HIGH",
                cvss="8.1", cwe="CWE-601",
                cwe_name="URL Redirection to Untrusted Site",
                owasp="A01:2021",
                remediation="Strictly compare redirect_uri against an exact whitelist registered for the client_id. Match on full string (scheme + host + port + path). Reject ANY mismatch.",
                evidence_marker=f"GET {oauth_url}?...&redirect_uri={variant}&... -> HTTP {r.status_code} Location: {loc[:120]}",
            ))

    return standard_response(
        tool="oauth_redirect_bypass", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Tested {len(_BYPASS_VARIANTS)} redirect_uri bypass variants at {oauth_url}",
        raw_data={"oauth_redirect_bypass": {"oauth_url": oauth_url, "suspect": suspect,
                                              "spa_catchall": spa["is_spa"]}},
    )


def register(app):
    app.include_router(router)
