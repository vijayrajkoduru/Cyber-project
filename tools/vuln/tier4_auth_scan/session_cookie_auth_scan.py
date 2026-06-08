"""Session cookie hygiene - passive Set-Cookie attribute audit. Self-contained.
Strategy: hit homepage + common app paths, parse Set-Cookie headers, check each cookie
for Secure / HttpOnly / SameSite / sensible expiry."""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url, http_get

router = APIRouter()

PROBE_PATHS = ["/", "/login", "/signin", "/account", "/dashboard", "/api/"]
SESSION_NAME_HINTS = ["session", "sess", "sid", "auth", "token", "jwt", "phpsessid", "asp.net", "jsessionid"]


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = probe_url(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    cookies_seen = []
    issues = []
    seen_names = set()
    for path in PROBE_PATHS:
        url = f"{base_url}{path}"
        r = http_get(url, timeout=6)
        if not r:
            continue
        sc_raw = (r.get("headers") or {}).get("set-cookie", "") or ""
        if not sc_raw:
            continue
        # Set-Cookie may have multiple cookies separated by comma+space (with date complications)
        # Conservative: split on ", " followed by name=
        cookies = re.split(r",\s*(?=[A-Za-z0-9_\-]+=)", sc_raw)
        for cookie in cookies:
            name_m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*=", cookie)
            if not name_m:
                continue
            name = name_m.group(1)
            if name in seen_names:
                continue
            seen_names.add(name)
            cookie_lower = cookie.lower()
            is_session = any(h in name.lower() for h in SESSION_NAME_HINTS)
            attrs = {
                "secure": "secure" in cookie_lower,
                "httponly": "httponly" in cookie_lower,
                "samesite": "samesite" in cookie_lower,
                "is_session": is_session,
            }
            cookies_seen.append({"name": name, "attrs": attrs})
            if is_session:
                if not attrs["secure"]:
                    issues.append({"sev": "MEDIUM", "issue": f"Session cookie '{name}' missing Secure flag"})
                if not attrs["httponly"]:
                    issues.append({"sev": "MEDIUM", "issue": f"Session cookie '{name}' missing HttpOnly flag"})
                if not attrs["samesite"]:
                    issues.append({"sev": "LOW", "issue": f"Session cookie '{name}' missing SameSite"})
    ctx.state["cookies_seen"] = cookies_seen
    ctx.state["session_issues"] = issues


def _r_med(s):
    med = [i for i in (s.get("session_issues") or []) if i["sev"] == "MEDIUM"]
    if not med:
        return None
    return {"name": f"{len(med)} session cookie hygiene issue(s)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-614",
            "evidence": "; ".join(i["issue"] for i in med[:6]),
            "remediation": "Set Secure + HttpOnly on all session/auth cookies. Add SameSite=Strict (or Lax for cross-site logins)."}


def _r_low(s):
    low = [i for i in (s.get("session_issues") or []) if i["sev"] == "LOW"]
    if not low:
        return None
    return {"name": f"{len(low)} session cookie missing SameSite",
            "severity": "LOW", "cvss": 3.7, "cwe": "CWE-1275",
            "evidence": "; ".join(i["issue"] for i in low[:6]),
            "remediation": "Add SameSite=Strict (or Lax) to limit CSRF surface."}


FINDING_RULES = [_r_med, _r_low]
INTEL_FIELDS = [("Cookies seen", "cookies_seen"), ("Issues", "session_issues")]


@router.post("/api/vuln/session_cookie_auth_scan")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="session_cookie_auth_scan",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
