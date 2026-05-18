"""JWT — alg=none + HMAC-secret crack + missing exp + PII."""
import base64, hashlib, hmac, json, re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
router = APIRouter()
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_SECRETS = ["secret","password","jwt","jwt-secret","jwtsecret","your-256-bit-secret",
    "your_jwt_secret","supersecret","supersecretkey","mysecret","test","admin","key",
    "private","changeme","123456","12345","1234567890","secret123","password123",
    "qwerty","default","abcdef","abc123","ssshhh","tokenkey","jwt_secret","JWT_SECRET",
    "JWTSecret","shhh","thisIsMySecretKey","0123456789abcdef"]

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

@router.post("/api/scan/jwt")
async def scan_jwt(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings, confirmed, tokens = [], [], []
    pages = 0

    # ── If the user authenticated (auto-login captured a bearer), test THAT
    # token directly — it's the real production JWT, complete with the real
    # signing key/alg. This catches alg=none / weak-secret / missing-exp on
    # apps like Juice Shop where the JWT is only returned to /rest/user/login
    # POST and would never be found by passive crawling.
    if getattr(req, "auth_bearer", None):
        tok = req.auth_bearer.strip()
        if tok and tok not in tokens:
            tokens.append(tok)
            _analyze(tok, findings, confirmed)

    for path in ["/", "/login", "/api/login", "/api/auth/login", "/api/me",
                 "/profile", "/account", "/settings", "/api/auth/me", "/api/user",
                 "/rest/user/whoami"]:
        pages += 1
        r = safe_get(base + path, req=req, allow_redirects=True, timeout=10)
        if r is None: continue
        haystack = " ".join([str(r.headers.get("Set-Cookie", "")),
                              str(r.headers.get("Authorization", "")),
                              (r.text or "")[:20000]])
        for tok in _JWT_RE.findall(haystack)[:5]:
            if tok not in tokens:
                tokens.append(tok)
                _analyze(tok, findings, confirmed)
    if not tokens:
        return standard_response(tool="jwt", target=req.target, findings=[],
            tests_performed=pages, vulnerable=False,
            skipped_reason=f"No JWT tokens found across {pages} crawled endpoints")
    return standard_response(tool="jwt", target=req.target, findings=findings,
        tests_performed=pages,
        tests_summary=f"JWT: crawled {pages} endpoints, found {len(tokens)} token(s); checked alg=none + crack against {len(_SECRETS)} secrets + missing exp + PII",
        raw_data={"jwt": {"tokens_found": len(tokens), "issues_confirmed": confirmed}})
def register(app): app.include_router(router)
