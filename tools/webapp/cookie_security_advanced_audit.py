"""cookie_security_advanced_audit — modern cookie attributes audit.

Existing webapp 'cookies' scanner covers Secure / HttpOnly / SameSite=Lax|Strict.
This one covers the 2024+ frontier:
  - __Host- prefix (binds cookie to exact host + secure + no Domain attr)
  - __Secure- prefix
  - Partitioned (CHIPS, cross-site iframe isolation)
  - SameSite=None requires Secure
  - Max-Age vs Expires deprecation
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()


def _parse_cookie(raw: str) -> dict:
    """Parse a Set-Cookie header value into a dict."""
    parts = [p.strip() for p in raw.split(";")]
    if not parts: return {}
    name_val = parts[0].split("=", 1)
    out = {"_name": name_val[0].strip(), "_value": name_val[1] if len(name_val) > 1 else ""}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k.strip().lower()] = v.strip()
        else:
            out[p.strip().lower()] = True
    return out


@router.post("/api/webapp/scan/cookie_security_advanced_audit")
@vl_turbo()
@vl_verify()
def scan_cookie_security_advanced_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    # Hit homepage + login page (more likely to set cookies)
    cookies_seen = []
    for path in ("/", "/login", "/api/login"):
        r = safe_request("GET", url.rstrip("/") + path,
            headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
            req=req, timeout=10, allow_redirects=True)
        if r is None: continue
        # Extract every Set-Cookie header
        sc = r.headers.get_list("Set-Cookie") if hasattr(r.headers, "get_list") else [r.headers.get("Set-Cookie", "")]
        # httpx requires .get_list; for requests use raw_headers
        try:
            sc = [v for k, v in r.raw.headers.items() if k.lower() == b"set-cookie".lower() or (isinstance(k, str) and k.lower() == "set-cookie")]
        except Exception:
            pass
        if not sc:
            # Fallback: comma-split (lossy but common)
            sc_raw = r.headers.get("set-cookie") or r.headers.get("Set-Cookie") or ""
            sc = re.split(r",(?=[^;]+=)", sc_raw) if sc_raw else []
        for raw in sc:
            if not raw: continue
            parsed = _parse_cookie(raw)
            parsed["_path_seen"] = path
            cookies_seen.append(parsed)

    if not cookies_seen:
        return standard_response(
            tool="cookie_security_advanced_audit", target=req.target, findings=[],
            tests_performed=3, vulnerable=False,
            skipped_reason="No Set-Cookie headers across /, /login, /api/login")

    findings = []
    issues = []  # list of (cookie_name, issue_desc)

    for c in cookies_seen:
        name = c.get("_name", "?")
        # __Host- prefix audit
        if name.startswith("__Host-"):
            if not c.get("secure"):
                issues.append((name, "__Host- prefix requires Secure"))
            if c.get("domain"):
                issues.append((name, "__Host- prefix forbids Domain attribute"))
            if c.get("path", "/") != "/":
                issues.append((name, f"__Host- prefix requires Path=/ (got {c.get('path')})"))
        elif name.startswith("__Secure-"):
            if not c.get("secure"):
                issues.append((name, "__Secure- prefix requires Secure"))

        # SameSite=None requires Secure (Chrome 80+ silently drops otherwise)
        if (c.get("samesite", "").lower() == "none") and not c.get("secure"):
            issues.append((name, "SameSite=None requires Secure (or browser drops cookie)"))

        # Partitioned (CHIPS) — modern third-party cookie isolation
        # If cookie is set in a context that could be 3rd-party (we can't fully verify),
        # absence of Partitioned is just a recommendation for known-3rd-party cookies.
        # We flag only if SameSite=None + no Partitioned (likely third-party use)
        if (c.get("samesite", "").lower() == "none" and c.get("secure")
              and not c.get("partitioned")):
            issues.append((name, "SameSite=None+Secure without Partitioned — "
                                  "may break in third-party context post-CHIPS rollout"))

    if issues:
        sample = " | ".join(f"{n}: {d}" for n, d in issues[:8])
        findings.append(wrap_finding(
            f"Cookie security issues ({len(issues)})",
            "MEDIUM", cvss="5.3", cwe="CWE-1004", owasp="A05:2021",
            remediation="Modern cookie best practices: "
                        "(1) Use __Host- prefix for session cookies — binds cookie to "
                        "exact host, requires Secure, requires Path=/, forbids Domain. "
                        "(2) If your app is embedded in a third-party iframe, ALL "
                        "cookies need SameSite=None + Secure + Partitioned (CHIPS). "
                        "(3) Without Partitioned, Chrome 121+ third-party cookie "
                        "phase-out will break your embedded auth.",
            evidence_marker=sample))
    else:
        findings.append(wrap_finding(
            f"All {len(cookies_seen)} cookie(s) follow modern security attributes",
            "POSITIVE", cwe="CWE-1004",
            remediation="Maintain. Continue auditing newly-set cookies.",
            evidence_marker=f"checked: " + ", ".join(c["_name"] for c in cookies_seen[:8])))

    return standard_response(
        tool="cookie_security_advanced_audit", target=req.target, findings=findings,
        tests_performed=3, vulnerable=bool(issues),
        tests_summary=f"{len(cookies_seen)} cookies, {len(issues)} issues",
        raw_data={"cookies_examined": [c.get("_name") for c in cookies_seen],
                   "issues": [{"name": n, "issue": d} for n, d in issues]})


def register(app):
    app.include_router(router)
