"""JWT/Bearer token hygiene - passive token inspection. Self-contained.
Strategy: probe common API endpoints, inspect Authorization+Set-Cookie+response body
for JWTs. Decode header+payload, flag alg:none, weak HS256 secret hint, expired, no exp."""
import re
import time
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async, decode_jwt

router = APIRouter()

PROBE_PATHS = ["/", "/api/", "/api/v1/", "/api/auth", "/api/me", "/me", "/.well-known/openid-configuration"]
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    tokens_seen = []
    issues = []
    for path in PROBE_PATHS:
        url = f"{base_url}{path}"
        r = await http_get_async(url, timeout=8, read=40000)
        if not r:
            continue
        haystack = " ".join([
            r.get("body", ""),
            r.get("headers", {}).get("authorization", "") or "",
            r.get("headers", {}).get("set-cookie", "") or "",
        ])
        for m in JWT_RE.finditer(haystack):
            token = m.group(0)
            if token in tokens_seen:
                continue
            tokens_seen.append(token)
            hdr, payload = decode_jwt(token)
            if not hdr:
                continue
            alg = (hdr.get("alg") or "").lower()
            if alg == "none":
                issues.append({"sev": "CRITICAL", "issue": f"JWT uses alg=none (signature bypass): {path}"})
            elif alg == "hs256":
                issues.append({"sev": "MEDIUM", "issue": f"JWT uses HS256 (shared-secret) at {path} - vulnerable to secret-cracking if leaked"})
            if payload and "exp" not in payload:
                issues.append({"sev": "MEDIUM", "issue": f"JWT has no exp claim (never expires): {path}"})
            elif payload and isinstance(payload.get("exp"), (int, float)) and payload["exp"] < time.time():
                issues.append({"sev": "LOW", "issue": f"JWT is expired (server still served it): {path}"})
            if hdr.get("jku") or hdr.get("x5u"):
                issues.append({"sev": "HIGH", "issue": f"JWT header has jku/x5u (SSRF surface): {path}"})
    ctx.state["jwts_found"] = len(tokens_seen)
    ctx.state["jwt_issues"] = issues


def _r_crit(s):
    crit = [i for i in (s.get("jwt_issues") or []) if i["sev"] == "CRITICAL"]
    if not crit:
        return None
    return {"name": f"{len(crit)} CRITICAL JWT issue(s)", "severity": "CRITICAL", "cvss": 9.8,
            "cwe": "CWE-347", "evidence": "; ".join(i["issue"] for i in crit),
            "remediation": "Reject alg=none. Pin signing algorithm in verifier."}


def _r_high(s):
    high = [i for i in (s.get("jwt_issues") or []) if i["sev"] == "HIGH"]
    if not high:
        return None
    return {"name": f"{len(high)} HIGH-severity JWT issue(s)", "severity": "HIGH", "cvss": 7.5,
            "cwe": "CWE-347", "evidence": "; ".join(i["issue"] for i in high),
            "remediation": "Disable jku/x5u (or pin to internal allow-list). Pin algorithm explicitly."}


def _r_med(s):
    med = [i for i in (s.get("jwt_issues") or []) if i["sev"] in ("MEDIUM", "LOW")]
    if not med:
        return None
    return {"name": f"{len(med)} JWT hygiene issue(s)", "severity": "MEDIUM", "cvss": 5.3,
            "cwe": "CWE-613", "evidence": "; ".join(i["issue"] for i in med),
            "remediation": "Always set exp claim; prefer asymmetric (RS256/ES256) over HS256."}


FINDING_RULES = [_r_crit, _r_high, _r_med]
INTEL_FIELDS = [("JWTs observed", "jwts_found"), ("JWT issues", "jwt_issues")]


@router.post("/api/vuln/bearer_jwt_auth_scan")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="bearer_jwt_auth_scan",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
