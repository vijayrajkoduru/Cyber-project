"""JWT — alg=none + HMAC-secret crack + missing exp + PII.

Secret dictionary: AI-curated 695-entry wordlist at
tools/_payloads/vuln/jwt_secrets.txt (loaded once at import, falls back
to a 32-entry hardcoded baseline if the file is missing).
"""
"""VL-VERIFY: JWT bundles can contain sample tokens (CodeMirror demos, JWT
debugger fixtures) that match the eyJ.eyJ regex. SPA catch-all returns the
same bundle for every probed path, so any token in the bundle would be
found over and over. Per-path check: if response body matches the canary
shell, skip - any token in it is a bundle-static fixture, not a real
session token leak.
"""
import base64, hashlib, hmac, json, re, time
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools.webapp._webapp_common import vuln_response, precheck_target
from tools._payloads.webapp._loader import load_lines
from tools._vl_core.spa_canary import detect_spa_catchall_sync, is_same_as_canary
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify
router = APIRouter()
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_FALLBACK_SECRETS = ["secret","password","jwt","jwt-secret","jwtsecret","your-256-bit-secret",
    "your_jwt_secret","supersecret","supersecretkey","mysecret","test","admin","key",
    "private","changeme","123456","12345","1234567890","secret123","password123",
    "qwerty","default","abcdef","abc123","ssshhh","tokenkey","jwt_secret","JWT_SECRET",
    "JWTSecret","shhh","thisIsMySecretKey","0123456789abcdef"]
_SECRETS = load_lines("jwt_secrets", fallback=_FALLBACK_SECRETS)

def _b64d(s):
    pad = "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)
def _parse(t):
    parts = t.split(".")
    if len(parts) != 3: return None
    try:
        return (json.loads(_b64d(parts[0])), json.loads(_b64d(parts[1])),
                _b64d(parts[2]), (parts[0]+"."+parts[1]).encode())
    except: return None
def _crack(si, sig, alg):
    fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if not fn: return None
    for s in _SECRETS:
        if hmac.compare_digest(hmac.new(s.encode(), si, fn).digest(), sig): return s
    return None

def _analyze(token, findings, confirmed):
    p = _parse(token)
    if not p: return
    header, payload, sig, si = p
    alg = (header.get("alg") or "").upper()
    if alg in ("NONE", ""):
        findings.append(wrap_finding(
            "JWT uses alg=none — signature can be bypassed",
            "CRITICAL", cvss="9.8", cwe="CWE-345", owasp="A02:2021",
            remediation="Never accept alg=none. Hard-code accepted algorithms (HS256 only or RS256 only) in JWT library config.",
            evidence_marker=f"JWT header alg={header.get('alg')!r}"))
        confirmed.append({"issue": "alg_none"})
    if alg.startswith("HS"):
        secret = _crack(si, sig, alg)
        if secret:
            findings.append(wrap_finding(
                f"JWT signed with weak HMAC secret: {secret!r}",
                "CRITICAL", cvss="9.1", cwe="CWE-326", owasp="A02:2021",
                remediation="Generate a long random secret (32+ bytes via secrets.token_urlsafe). Never use dictionary words. Rotate secret + invalidate existing tokens.",
                evidence_marker=f"JWT signature verified with secret={secret!r}"))
            confirmed.append({"issue": "weak_secret", "secret": secret})
    if "exp" not in payload:
        findings.append(wrap_finding(
            "JWT has no 'exp' claim — tokens never expire",
            "HIGH", cvss="7.5", cwe="CWE-613", owasp="A07:2021",
            remediation="Always set 'exp' claim. 15 min for access tokens, longer for refresh tokens. Verify exp on every request.",
            evidence_marker=f"JWT payload keys: {sorted(payload.keys())}"))
        confirmed.append({"issue": "no_exp"})
    pii = [k for k in payload if "password" in k.lower() or k.lower() in ("ssn", "credit_card", "cc_number")]
    if pii:
        findings.append(wrap_finding(
            f"JWT payload contains sensitive PII: {', '.join(pii)}",
            "HIGH", cvss="7.5", cwe="CWE-522", owasp="A02:2021",
            remediation="JWT payload is base64-encoded, NOT encrypted. Remove sensitive data; store server-side and reference by id.",
            evidence_marker=f"JWT payload contains: {pii}"))
        confirmed.append({"issue": "sensitive_pii", "fields": pii})

@router.post("/api/webapp/scan/jwt")
@vl_turbo()
@vl_verify()
def scan_jwt(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    spa_suppressed = []
    findings, confirmed, tokens = [], [], []
    pages = 0
    # VL-TURBO wall-clock cap: 11 page crawls × 10s × 3 retries = up to ~5 min worst case.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 30.0
    _bailed = False

    # ── If the user authenticated (auto-login captured a bearer), test THAT
    # token directly — it's the real production JWT, complete with the real
    # signing key/alg.
    if getattr(req, "auth_bearer", None):
        tok = req.auth_bearer.strip()
        if tok and tok not in tokens:
            tokens.append(tok)
            _analyze(tok, findings, confirmed)

    for path in ["/", "/login", "/api/login", "/api/auth/login", "/api/me",
                 "/profile", "/account", "/settings", "/api/auth/me", "/api/user",
                 "/rest/user/whoami"]:
        if time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
            _bailed = True; break
        pages += 1
        r = safe_get(base + path, req=req, allow_redirects=True, timeout=6, retries=0)
        if r is None: continue
        # SPA catch-all: body matches canary -> JWTs in it are bundle-static
        if spa["is_spa"] and is_same_as_canary(r.text or "", spa["canary_body"]):
            spa_suppressed.append(path)
            continue
        haystack = " ".join([str(r.headers.get("Set-Cookie", "")),
                              str(r.headers.get("Authorization", "")),
                              (r.text or "")[:20000]])
        for tok in _JWT_RE.findall(haystack)[:5]:
            if tok not in tokens:
                tokens.append(tok)
                _analyze(tok, findings, confirmed)
    if not tokens:
        reason = f"No JWT tokens found across {pages} crawled endpoints"
        if _bailed:
            reason += f" (wall-clock bailed at {_WALLCLOCK_BUDGET}s)"
        return vuln_response(tool="jwt", target=req.target, findings=[],
            tested=max(pages, 1), skipped_reason=reason,
            raw_data={"jwt": {"tokens_found": 0, "wallclock_bailed": _bailed}})
    summary = (f"JWT: crawled {pages} endpoints in {time.time() - _wallclock_start:.1f}s, "
               f"found {len(tokens)} token(s); checked alg=none + crack against "
               f"{len(_SECRETS)} secrets + missing exp + PII")
    if _bailed:
        summary += f" — VL-TURBO wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    return vuln_response(tool="jwt", target=req.target, findings=findings,
        tested=pages,
        what_checked=f"JWT tokens for alg=none, weak HMAC secrets ({len(_SECRETS)}-entry AI-curated wordlist), missing exp, PII leakage",
        tests_summary=summary,
        raw_data={"jwt": {"tokens_found": len(tokens), "issues_confirmed": confirmed,
                          "secret_dictionary_size": len(_SECRETS),
                          "wallclock_bailed": _bailed,
                          "spa_catchall": spa["is_spa"],
                          "spa_suppressed_paths": spa_suppressed}})
def register(app): app.include_router(router)
