"""JWT/Bearer token hygiene. VL-METHOD Wave 4.

Refactored 2026-06-09 to MethodologyScanner. Verify refetches the same endpoint
and re-decodes the JWT — if the same issue (alg=none / no exp / jku set / etc.)
appears in the refetched token, finding is CONFIRMED; if the token rotated and
the issue is gone, finding is SUSPECTED.
"""
import re, time
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async, decode_jwt
from tools._vl_core.verify import vl_verify

router = APIRouter()

PROBE_PATHS_QUICK = ["/", "/api/", "/.well-known/openid-configuration"]
PROBE_PATHS_DEEP  = ["/api/v1/", "/api/auth", "/api/me", "/me"]
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


def _audit_token(token, path):
    issues = []
    hdr, payload = decode_jwt(token)
    if not hdr:
        return issues
    alg = (hdr.get("alg") or "").lower()
    if alg == "none":
        issues.append({"sev": "CRITICAL", "issue": f"JWT uses alg=none (signature bypass): {path}",
                       "kind": "alg-none", "path": path})
    elif alg == "hs256":
        issues.append({"sev": "MEDIUM", "issue": f"JWT uses HS256 (shared-secret) at {path}",
                       "kind": "hs256", "path": path})
    if payload and "exp" not in payload:
        issues.append({"sev": "MEDIUM", "issue": f"JWT has no exp claim (never expires): {path}",
                       "kind": "no-exp", "path": path})
    elif payload and isinstance(payload.get("exp"), (int, float)) and payload["exp"] < time.time():
        issues.append({"sev": "LOW", "issue": f"JWT is expired (server still served it): {path}",
                       "kind": "expired", "path": path})
    if hdr.get("jku") or hdr.get("x5u"):
        issues.append({"sev": "HIGH", "issue": f"JWT header has jku/x5u (SSRF surface): {path}",
                       "kind": "jku-x5u", "path": path})
    return issues


async def _scan_paths(base_url, paths):
    issues, tokens = [], set()
    for path in paths:
        r = await http_get_async(f"{base_url}{path}", timeout=8, read=40000)
        if not r:
            continue
        haystack = " ".join([
            r.get("body", ""),
            (r.get("headers", {}) or {}).get("authorization", "") or "",
            (r.get("headers", {}) or {}).get("set-cookie", "") or "",
        ])
        for m in JWT_RE.finditer(haystack):
            token = m.group(0)
            if token in tokens: continue
            tokens.add(token)
            issues.extend(_audit_token(token, path))
    return issues, len(tokens)


class BearerJwtAuthScan(MethodologyScanner):
    name = "bearer_jwt_auth_scan"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["jwts_found"] = 0
        ctx.state["jwt_issues"] = []
        return True

    async def fingerprint(self, ctx):
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {"server": (hdrs.get("server") or "")[:80]}

    async def quick_probe(self, ctx):
        issues, n = await _scan_paths(ctx.state["base_url"], PROBE_PATHS_QUICK)
        ctx.state["jwts_found"] += n
        ctx.state["jwt_issues"].extend(issues)
        ctx.state["quick_hits"] = issues
        return [dict(i) for i in issues]

    async def deep_scan(self, ctx):
        issues, n = await _scan_paths(ctx.state["base_url"], PROBE_PATHS_DEEP)
        ctx.state["jwts_found"] += n
        ctx.state["jwt_issues"].extend(issues)
        ctx.state["deep_hits"] = issues
        return [dict(i) for i in issues]

    async def verify(self, ctx, finding):
        # Refetch the same path - if the same issue kind shows up in any
        # JWT on the refetch, CONFIRMED. Otherwise token rotated cleanly.
        r = await http_get_async(f"{ctx.state['base_url']}{finding['path']}",
                                  timeout=8, read=40000)
        if not r:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "refetch-failed"
            return finding
        haystack = " ".join([
            r.get("body", ""),
            (r.get("headers", {}) or {}).get("authorization", "") or "",
            (r.get("headers", {}) or {}).get("set-cookie", "") or "",
        ])
        for m in JWT_RE.finditer(haystack):
            issues2 = _audit_token(m.group(0), finding["path"])
            if any(i["kind"] == finding["kind"] for i in issues2):
                finding["confidence"] = "CONFIRMED"
                finding["verification_method"] = "refetch-issue-stable"
                return finding
        finding["confidence"] = "SUSPECTED"
        finding["verification_method"] = "refetch-issue-gone"
        return finding


def _bucket(s, sev_pred, name, sev, cvss, cwe, remediation):
    verified = s.get("methodology_findings") or []
    matched = [f for f in verified if sev_pred(f.get("sev")) and f.get("confidence") == "CONFIRMED"]
    if not matched: return None
    return {"name": f"{name} ({len(matched)})", "severity": sev, "cvss": cvss, "cwe": cwe,
            "evidence": "; ".join(i["issue"] for i in matched),
            "remediation": remediation}


def _r_crit(s): return _bucket(s, lambda x: x == "CRITICAL", "CRITICAL JWT issue(s)",
                                 "CRITICAL", 9.8, "CWE-347",
                                 "Reject alg=none. Pin signing algorithm in verifier.")
def _r_high(s): return _bucket(s, lambda x: x == "HIGH", "HIGH-severity JWT issue(s)",
                                 "HIGH", 7.5, "CWE-347",
                                 "Disable jku/x5u (or pin to internal allow-list). Pin algorithm.")
def _r_med(s): return _bucket(s, lambda x: x in ("MEDIUM", "LOW"), "JWT hygiene issue(s)",
                                "MEDIUM", 5.3, "CWE-613",
                                "Always set exp claim; prefer asymmetric (RS256/ES256) over HS256.")


FINDING_RULES = [_r_crit, _r_high, _r_med]
INTEL_FIELDS = [
    ("JWTs observed", "jwts_found"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits", "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/bearer_jwt_auth_scan")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = BearerJwtAuthScan()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
