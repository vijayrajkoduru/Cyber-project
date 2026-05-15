"""JWT (JSON Web Token) security scanner.

Passive analysis — finds JWTs in responses, cookies, and headers,
then checks for common weaknesses:

  CRITICAL  alg=none           — anyone can forge tokens
  CRITICAL  weak HMAC secret   — verifies with common password (30 tried)
  HIGH      sensitive PII      — password/SSN/credit-card/API-key in payload
  MEDIUM    no exp claim       — token never expires
"""
import re
import json
import base64
import hmac
import hashlib
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url,
    safe_get, wrap_finding, standard_response,
)

router = APIRouter()


COMMON_SECRETS = [
    "secret", "key", "password", "123456", "your-256-bit-secret",
    "jwt_secret", "jwtsecret", "JWT_SECRET", "mysecret", "your-secret",
    "secret123", "supersecret", "topsecret", "test", "admin",
    "default", "changeme", "1234", "12345", "abc123",
    "qwerty", "iloveyou", "passw0rd", "letmein", "welcome",
    "secret-key", "my-secret-key", "shhh", "null", "",
]
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{0,}")
JWT_HUNT_PATHS = ["", "/login", "/auth/login", "/api/auth/login", "/api/login",
                  "/me", "/api/user/me", "/api/me", "/profile", "/account"]


def _b64url_decode(s):
    s = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def _decode_jwt(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts
    except Exception:
        return None


def _crack_hmac(parts, alg):
    if alg.upper() not in ("HS256", "HS384", "HS512"):
        return None
    signing_input = (parts[0] + "." + parts[1]).encode()
    try:
        expected_sig = _b64url_decode(parts[2])
    except Exception:
        return None
    hash_func = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg.upper()]
    for secret in COMMON_SECRETS:
        computed = hmac.new(secret.encode(), signing_input, hash_func).digest()
        if hmac.compare_digest(computed, expected_sig):
            return secret
    return None


def _find_jwts(response):
    jwts = set()
    body = response.text or ""
    for m in JWT_PATTERN.finditer(body):
        jwts.add(m.group(0))
    for c in response.cookies:
        for m in JWT_PATTERN.finditer(str(c.value or "")):
            jwts.add(m.group(0))
    for h in ("Authorization", "X-Auth-Token", "X-Access-Token", "Set-Cookie"):
        v = response.headers.get(h, "") or ""
        for m in JWT_PATTERN.finditer(v):
            jwts.add(m.group(0))
    return list(jwts)


@router.post("/api/scan/jwt")
async def scan_jwt(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    raw_results = []
    all_jwts = []

    for path in JWT_HUNT_PATHS:
        tests += 1
        page_url = base + path if path else base
        r = safe_get(page_url, req=req, allow_redirects=True, timeout=8)
        if r is None or r.status_code >= 500:
            continue
        for jwt in _find_jwts(r):
            if jwt not in [j["token"] for j in all_jwts]:
                all_jwts.append({"token": jwt, "found_on": page_url})

    if not all_jwts:
        return standard_response(
            tool="jwt", target=req.target, findings=[],
            tests_performed=tests, vulnerable=False,
            skipped_reason=f"No JWT tokens found across {tests} crawled endpoints",
            raw_data={"jwt": {"endpoints_checked": tests, "tokens_found": 0}},
        )

    for jwt_info in all_jwts:
        jwt = jwt_info["token"]
        decoded = _decode_jwt(jwt)
        if decoded is None:
            raw_results.append({**jwt_info, "result": "could not decode"})
            continue
        header, payload, parts = decoded
        alg = str(header.get("alg", ""))
        jwt_info["alg"] = alg
        jwt_info["claims"] = list(payload.keys())

        if alg.lower() == "none":
            findings.append(wrap_finding(
                "JWT uses 'none' algorithm — anyone can forge valid tokens",
                "CRITICAL", cwe="CWE-345", owasp="A07:2021",
                evidence_marker=f"JWT header: alg='{alg}' on {jwt_info['found_on']}. Token: {jwt[:60]}...",
                remediation="Require a strong signing algorithm (RS256/ES256 asymmetric, HS256 with 256-bit random secret). Reject 'alg':'none' explicitly.",
                tests_performed=1, cvss="9.8",
            ))

        if alg.upper() in ("HS256", "HS384", "HS512"):
            secret = _crack_hmac(parts, alg)
            if secret is not None:
                findings.append(wrap_finding(
                    f"JWT signed with weak/common secret: '{secret}'",
                    "CRITICAL", cwe="CWE-326", owasp="A02:2021",
                    evidence_marker=f"Token from {jwt_info['found_on']} verifies with HMAC secret '{secret}' ({alg})",
                    remediation="Rotate to a cryptographically random 256-bit secret (`openssl rand -base64 32`). Store in a secrets manager, never in source code. Consider RS256/ES256 for better key management.",
                    tests_performed=1, cvss="9.8",
                ))

        if "exp" not in payload:
            findings.append(wrap_finding(
                "JWT has no expiration claim — token never expires",
                "MEDIUM", cwe="CWE-613", owasp="A07:2021",
                evidence_marker=f"JWT payload from {jwt_info['found_on']} contains claims {list(payload.keys())} but no 'exp'",
                remediation="Add 'exp' claim to all JWTs. Recommended TTL: 15-30 min for access tokens, longer for refresh tokens with rotation.",
                tests_performed=1, cvss="5.5",
            ))

        payload_str = json.dumps(payload, default=str)
        sensitive_patterns = [
            (r'\b\d{3}[- ]?\d{2}[- ]?\d{4}\b', "SSN"),
            (r'\b(?:\d[ -]*?){13,16}\b', "credit card number"),
            (r'"password"\s*:\s*"[^"]+"', "password field"),
            (r'"api[_-]?key"\s*:\s*"[^"]+"', "API key"),
            (r'"secret"\s*:\s*"[^"]+"', "secret"),
        ]
        for pat, name in sensitive_patterns:
            if re.search(pat, payload_str, re.I):
                findings.append(wrap_finding(
                    f"JWT payload contains sensitive data: {name}",
                    "HIGH", cwe="CWE-200", owasp="A02:2021",
                    evidence_marker=f"JWT payload from {jwt_info['found_on']} contains {name} pattern. JWTs are signed, NOT encrypted.",
                    remediation=f"Never include {name} in JWT payload. JWTs are not encrypted — any client can decode. Store sensitive data server-side and reference by opaque ID.",
                    tests_performed=1, cvss="7.0",
                ))

        raw_results.append({**jwt_info, "result": "analyzed"})

    return standard_response(
        tool="jwt", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"Crawled {tests} endpoints; found {len(all_jwts)} JWT token(s); checked alg, secret strength ({len(COMMON_SECRETS)} secrets), exp, sensitive PII",
        raw_data={"jwt": {"endpoints_checked": tests, "tokens_found": len(all_jwts), "results": raw_results}},
    )


def register(app):
    app.include_router(router)
