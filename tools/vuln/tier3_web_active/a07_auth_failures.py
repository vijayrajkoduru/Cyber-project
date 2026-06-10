"""A07 Identification & Auth Failures - login/cookie hygiene check. VL-METHOD Wave 3.

Refactored 2026-06-09 to MethodologyScanner. Verify re-fetches the SAME login
page once more - cookie hygiene flags are static facts about the response,
so a stable refetch CONFIRMS them and a flaky refetch (status flip,
disappearing form) downgrades to SUSPECTED.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async
from tools._vl_core.verify import vl_verify

router = APIRouter()

LOGIN_PATHS_QUICK = ["/login", "/signin", "/account/login"]
LOGIN_PATHS_DEEP  = ["/user/login", "/admin/login", "/wp-login.php"]


def _audit_response(url, r):
    """Return list of (issue, severity) tuples for one login page response."""
    issues = []
    if not r or r.get("status", 0) >= 400:
        return issues
    body_lower = r.get("body", "").lower()
    if "<form" not in body_lower and "password" not in body_lower:
        return issues
    # Login form served over plain HTTP
    if url.startswith("http://"):
        issues.append({"issue": "Login form served over plain HTTP", "sev": "HIGH"})
    sc = (r.get("headers", {}) or {}).get("set-cookie", "") or ""
    if sc:
        if "secure" not in sc.lower():
            issues.append({"issue": "Session cookie without Secure flag", "sev": "MEDIUM"})
        if "httponly" not in sc.lower():
            issues.append({"issue": "Session cookie without HttpOnly flag", "sev": "MEDIUM"})
        if "samesite" not in sc.lower():
            issues.append({"issue": "Session cookie without SameSite", "sev": "LOW"})
    if 'type="password"' in body_lower and \
       'autocomplete="off"' not in body_lower and \
       'autocomplete="new-password"' not in body_lower:
        issues.append({"issue": "Password field allows browser autocomplete", "sev": "LOW"})
    return issues


async def _scan_paths(base_url, paths):
    login_found, all_issues = [], []
    for path in paths:
        url = f"{base_url}{path}"
        r = await http_get_async(url, timeout=8, read=20000)
        if not r or r.get("status", 0) >= 400:
            continue
        issues = _audit_response(url, r)
        if not issues and "<form" not in (r.get("body", "") or "").lower():
            continue
        login_found.append(path)
        for i in issues:
            all_issues.append({"path": path, **i})
        break       # one login page is enough per pass
    return login_found, all_issues


class A07AuthFailures(MethodologyScanner):
    name = "a07_auth_failures"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["login_paths"] = []
        ctx.state["auth_issues"] = []
        return True

    async def fingerprint(self, ctx):
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {
                "server": (hdrs.get("server") or "")[:80],
            }

    async def quick_probe(self, ctx):
        paths, issues = await _scan_paths(ctx.state["base_url"], LOGIN_PATHS_QUICK)
        ctx.state["login_paths"].extend(paths)
        ctx.state["auth_issues"].extend(issues)
        ctx.state["quick_hits"] = issues
        return [dict(i) for i in issues]

    async def deep_scan(self, ctx):
        # Only scan deep paths if quick found nothing
        if ctx.state.get("login_paths"):
            ctx.state["deep_hits"] = []
            return []
        paths, issues = await _scan_paths(ctx.state["base_url"], LOGIN_PATHS_DEEP)
        ctx.state["login_paths"].extend(paths)
        ctx.state["auth_issues"].extend(issues)
        ctx.state["deep_hits"] = issues
        return [dict(i) for i in issues]

    async def verify(self, ctx, finding):
        url = f"{ctx.state['base_url']}{finding['path']}"
        r = await http_get_async(url, timeout=8, read=20000)
        if not r or r.get("status", 0) >= 400:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "refetch-non-2xx"
            return finding
        issues2 = _audit_response(url, r)
        # Look for the same issue in the refetch
        same = next((i for i in issues2 if i["issue"] == finding["issue"]), None)
        if same:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "refetch-issue-stable"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "refetch-issue-gone"
        return finding


def _r_high(s):
    verified = s.get("methodology_findings") or []
    high = [f for f in verified if f.get("sev") == "HIGH" and f.get("confidence") == "CONFIRMED"]
    if not high:
        return None
    return {"name": f"{len(high)} HIGH auth-hygiene issue(s) (CONFIRMED)",
            "severity": "HIGH", "cvss": 7.4, "cwe": "CWE-319",
            "evidence": "; ".join(f"{f['path']}: {f['issue']}" for f in high),
            "remediation": "Serve login over HTTPS only. Enforce HSTS."}


def _r_med(s):
    verified = s.get("methodology_findings") or []
    med = [f for f in verified
            if f.get("sev") in ("MEDIUM", "LOW") and f.get("confidence") == "CONFIRMED"]
    if not med:
        return None
    return {"name": f"{len(med)} auth/session hygiene weakness(es) (CONFIRMED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-614",
            "evidence": "; ".join(f"{f['path']}: {f['issue']}" for f in med),
            "remediation": "Set Secure, HttpOnly, SameSite=Strict on all session cookies."}


def _r_susp(s):
    verified = s.get("methodology_findings") or []
    susp = [f for f in verified if f.get("confidence") == "SUSPECTED"]
    if not susp:
        return None
    return {"name": f"{len(susp)} auth-hygiene issue(s) didn't reproduce on refetch (SUSPECTED)",
            "severity": "LOW", "cvss": 2.0, "cwe": "CWE-614",
            "evidence": "; ".join(f"{f['path']}: {f['issue']}" for f in susp),
            "remediation": "Manually re-inspect each finding."}


FINDING_RULES = [_r_high, _r_med, _r_susp]
INTEL_FIELDS = [
    ("Login pages found", "login_paths"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits", "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/a07_auth_failures")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = A07AuthFailures()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
