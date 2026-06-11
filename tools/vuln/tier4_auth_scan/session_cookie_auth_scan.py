"""Session cookie hygiene. VL-METHOD Wave 4.

Refactored 2026-06-09 to MethodologyScanner. Verify refetches the path
that produced the cookie hygiene issue. If the same Set-Cookie still
lacks the same attribute, CONFIRMED. Catches cookies that rotate per
request and only sometimes miss flags.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async
from tools._vl_core.verify import vl_verify

router = APIRouter()

PROBE_PATHS_QUICK = ["/", "/login", "/signin"]
PROBE_PATHS_DEEP  = ["/account", "/dashboard", "/api/"]
SESSION_NAME_HINTS = ["session", "sess", "sid", "auth", "token", "jwt",
                       "phpsessid", "asp.net", "jsessionid"]


def _audit_cookies(url, r):
    """Return (cookies_seen, issues) for one response."""
    cookies_seen, issues = [], []
    sc_raw = ((r.get("headers") or {}).get("set-cookie", "") or "")
    if not sc_raw: return cookies_seen, issues
    cookies = re.split(r",\s*(?=[A-Za-z0-9_\-]+=)", sc_raw)
    for cookie in cookies:
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*=", cookie)
        if not m: continue
        name = m.group(1)
        clower = cookie.lower()
        is_session = any(h in name.lower() for h in SESSION_NAME_HINTS)
        attrs = {
            "secure":    "secure"   in clower,
            "httponly":  "httponly" in clower,
            "samesite":  "samesite" in clower,
            "is_session": is_session,
        }
        cookies_seen.append({"name": name, "attrs": attrs})
        if is_session:
            if not attrs["secure"]:
                issues.append({"sev": "MEDIUM", "name": name, "attr": "Secure",
                               "url": url, "issue": f"Session cookie '{name}' missing Secure flag"})
            if not attrs["httponly"]:
                issues.append({"sev": "MEDIUM", "name": name, "attr": "HttpOnly",
                               "url": url, "issue": f"Session cookie '{name}' missing HttpOnly flag"})
            if not attrs["samesite"]:
                issues.append({"sev": "LOW", "name": name, "attr": "SameSite",
                               "url": url, "issue": f"Session cookie '{name}' missing SameSite"})
    return cookies_seen, issues


async def _scan_one(base_url, path):
    url = f"{base_url}{path}"
    r = await http_get_async(url, timeout=6)
    if not r:
        return (url, [], [])
    cookies, issues = _audit_cookies(url, r)
    return (url, cookies, issues)


async def _scan(base_url, paths):
    # VL-TURBO deep: fetch all paths concurrently.
    # Was 3 sequential GETs at 6s = ~18s. Now ~6s.
    results = await asyncio.gather(
        *[_scan_one(base_url, p) for p in paths],
        return_exceptions=True)
    all_cookies, all_issues = [], []
    seen_names = set()
    for res in results:
        if isinstance(res, BaseException):
            continue
        _url, cookies, issues = res
        for c in cookies:
            if c["name"] not in seen_names:
                seen_names.add(c["name"])
                all_cookies.append(c)
        all_issues.extend(issues)
    return all_cookies, all_issues


class SessionCookieAuthScan(MethodologyScanner):
    name = "session_cookie_auth_scan"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["cookies_seen"] = []
        ctx.state["session_issues"] = []
        return True

    async def fingerprint(self, ctx):
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {"server": (hdrs.get("server") or "")[:80]}

    async def quick_probe(self, ctx):
        cookies, issues = await _scan(ctx.state["base_url"], PROBE_PATHS_QUICK)
        ctx.state["cookies_seen"].extend(cookies)
        ctx.state["session_issues"].extend(issues)
        ctx.state["quick_hits"] = issues
        return [dict(i) for i in issues]

    async def deep_scan(self, ctx):
        cookies, issues = await _scan(ctx.state["base_url"], PROBE_PATHS_DEEP)
        ctx.state["cookies_seen"].extend(cookies)
        ctx.state["session_issues"].extend(issues)
        ctx.state["deep_hits"] = issues
        return [dict(i) for i in issues]

    async def verify(self, ctx, finding):
        r = await http_get_async(finding["url"], timeout=6)
        if not r:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "refetch-failed"
            return finding
        _, issues2 = _audit_cookies(finding["url"], r)
        same = any(i["name"] == finding["name"] and i["attr"] == finding["attr"]
                    for i in issues2)
        if same:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "refetch-attr-still-missing"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "refetch-cookie-rotated-or-fixed"
        return finding


def _r_med(s):
    verified = s.get("methodology_findings") or []
    med = [f for f in verified if f.get("sev") == "MEDIUM" and f.get("confidence") == "CONFIRMED"]
    if not med: return None
    return {"name": f"{len(med)} session cookie hygiene issue(s) (CONFIRMED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-614",
            "evidence": "; ".join(i["issue"] for i in med[:6]),
            "remediation": "Set Secure + HttpOnly on all session/auth cookies. "
                            "Add SameSite=Strict (or Lax for cross-site logins)."}


def _r_low(s):
    verified = s.get("methodology_findings") or []
    low = [f for f in verified if f.get("sev") == "LOW" and f.get("confidence") == "CONFIRMED"]
    if not low: return None
    return {"name": f"{len(low)} session cookie missing SameSite (CONFIRMED)",
            "severity": "LOW", "cvss": 3.7, "cwe": "CWE-1275",
            "evidence": "; ".join(i["issue"] for i in low[:6]),
            "remediation": "Add SameSite=Strict (or Lax) to limit CSRF surface."}


FINDING_RULES = [_r_med, _r_low]
INTEL_FIELDS = [
    ("Cookies seen", "cookies_seen"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits", "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/session_cookie_auth_scan")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = SessionCookieAuthScan()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
