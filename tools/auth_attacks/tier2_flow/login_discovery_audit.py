"""Autonomous login-surface audit (auth_attacks, tier2).

ZERO-INPUT: auto-discovers the login endpoint, then runs black-box auth checks
so the module produces real findings without the user supplying tokens/creds —
the rest of the auth_attacks tiers need manual inputs and otherwise skip.

Checks (all detection-only + non-destructive — dummy credentials, small request
counts, NO account creation):
  - login endpoint discovery (probe common API/form paths)
  - rate-limiting / account-lockout on the login endpoint
  - username/account enumeration via differing responses
  - session-cookie flags (HttpOnly / Secure / SameSite)
  - JWT-based auth detection (so jwt_secret_audit can be pointed at it)

Returns the standard scanner response shape, so the auth_attacks orchestrator
(run_all) aggregates it like every other tool.
"""
import asyncio
import base64
import json
import re
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, safe_request,
                            wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 45

# Common login endpoints across frameworks + the bundled labs (juiceshop =
# /rest/user/login). Ordered roughly most-specific -> generic.
_LOGIN_PATHS = [
    "/rest/user/login", "/api/auth/login", "/api/v1/auth/login", "/api/login",
    "/api/v1/login", "/api/sessions", "/api/session", "/api/users/login",
    "/api/account/login", "/api/authenticate", "/auth/login", "/user/login",
    "/account/login", "/signin", "/login",
]

# Obviously-fake credentials — never a real account, so the probes are safe.
_DUMMY = {"email": "vl-probe-noexist@example.invalid",
          "username": "vl-probe-noexist",
          "password": "VlProbe_Inv4lid!9183"}

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")


def _base(target: str) -> str:
    t = (target or "").strip()
    if not t.lower().startswith(("http://", "https://")):
        t = "http://" + t          # labs are http; redirects upgrade to https
    return t.rstrip("/")


def _post(req, url, mech, creds):
    if mech == "form":
        return safe_request("POST", url, req=req, timeout=8, data=creds, allow_redirects=False)
    return safe_request("POST", url, req=req, timeout=8, json=creds, allow_redirects=False)


def _setcookies(resp):
    """Raw Set-Cookie header lines (so we can read HttpOnly/Secure/SameSite that
    the parsed cookie jar drops)."""
    try:
        return list(resp.raw.headers.getlist("Set-Cookie"))
    except Exception:
        sc = resp.headers.get("Set-Cookie") if resp is not None else None
        return [sc] if sc else []


def _extract_jwt(text):
    m = _JWT_RE.search(text or "")
    if not m:
        return None
    tok = m.group(0)
    try:
        h = tok.split(".")[0]; h += "=" * (-len(h) % 4)
        hdr = json.loads(base64.urlsafe_b64decode(h))
        p = tok.split(".")[1]; p += "=" * (-len(p) % 4)
        pl = json.loads(base64.urlsafe_b64decode(p))
        return {"alg": hdr.get("alg"), "typ": hdr.get("typ"),
                "claims": sorted(list(pl.keys()))[:10]}
    except Exception:
        return {"alg": "?", "typ": "?", "claims": []}


def _discover_login(req, base):
    opts = req.options or {}
    explicit = (opts.get("login_url") or "").strip()
    if explicit:
        p = urlparse(explicit).path or explicit
        paths = [p if p.startswith("/") else "/" + p]
    else:
        paths = _LOGIN_PATHS
    best = None
    for p in paths:
        url = base + p
        for mech in ("json", "form"):
            r = _post(req, url, mech, dict(_DUMMY))
            if r is None:
                continue
            sc = r.status_code
            if sc in (404, 405, 501):
                continue
            body = (r.text or "")[:3000]
            low = body.lower()
            authish = any(k in low for k in (
                "password", "credential", "invalid", "unauthor", "token",
                "email or password", "authentication", "incorrect"))
            # A login endpoint answers a credential POST with 401/403 (clear), or
            # 400/422/200 mentioning auth. 404/405 above already filtered out.
            if sc in (401, 403) or (sc in (400, 422, 200) and authish):
                cand = {"path": p, "mech": mech, "status": sc, "resp": r,
                        "jwt": _extract_jwt(body),
                        "score": (2 if sc in (401, 403) else 1)
                                 + (1 if authish else 0)}
                if best is None or cand["score"] > best["score"]:
                    best = cand
                break
        if best and best["score"] >= 3:
            break
    return best


def _check_rate_limit(req, base, path, mech):
    url = base + path
    statuses = []
    throttled = False
    for _ in range(7):
        r = _post(req, url, mech, dict(_DUMMY))
        if r is None:
            continue
        statuses.append(r.status_code)
        low = (r.text or "")[:500].lower()
        if (r.status_code == 429 or r.headers.get("Retry-After")
                or any(k in low for k in ("too many", "rate limit", "locked",
                                          "try again later", "temporarily"))):
            throttled = True
            break
    ev = f"{len(statuses)} rapid failed logins -> statuses {statuses}"
    ev += " (throttle/lockout signal seen)" if throttled else " (no 429 / Retry-After / lockout)"
    return {"n": len(statuses), "throttled": throttled, "evidence": ev}


def _check_enum(req, base, path, mech):
    host = urlparse(base).hostname or "test.invalid"
    likely = {"email": f"admin@{host}", "username": "admin",
              "password": "Wrong_Pass_123!"}
    rando = {"email": "zzqq-noexist-vlx@example.invalid",
             "username": "zzqq_noexist_vlx", "password": "Wrong_Pass_123!"}
    ra = _post(req, url=base + path, mech=mech, creds=likely)
    rb = _post(req, url=base + path, mech=mech, creds=rando)
    if ra is None or rb is None:
        return {"n": 2, "tested": False, "enumerable": False,
                "evidence": "enumeration probe inconclusive (no response)"}

    def _norm(r, creds):
        b = (r.text or "")[:1500].lower()
        for v in creds.values():
            b = b.replace(str(v).lower(), "")
        return b
    na, nb = _norm(ra, likely), _norm(rb, rando)
    diff_status = ra.status_code != rb.status_code
    notfound = any(k in (na + nb) for k in (
        "not found", "no account", "does not exist", "unknown user",
        "no such user", "no user", "user not registered"))
    enumerable = diff_status or (na != nb and notfound)
    ev = f"known-user -> {ra.status_code}, random-user -> {rb.status_code}"
    ev += " (responses differ -> enumerable)" if enumerable else " (responses equivalent)"
    return {"n": 2, "tested": True, "enumerable": enumerable, "evidence": ev}


def _check_cookie_flags(req, base, login):
    raw = []
    if login.get("resp") is not None:
        raw += _setcookies(login["resp"])
    g = safe_request("GET", base, req=req, timeout=8)
    if g is not None:
        raw += _setcookies(g)
    https = base.lower().startswith("https://")
    out = []
    seen = set()
    for sc in raw:
        if not sc:
            continue
        name = sc.split("=", 1)[0].strip()
        if name in seen:
            continue
        if not any(k in name.lower() for k in (
                "sess", "sid", "token", "jwt", "auth", "connect.sid", "login")):
            continue
        seen.add(name)
        low = sc.lower()
        missing = []
        if "httponly" not in low:
            missing.append("HttpOnly")
        if https and "secure" not in low:
            missing.append("Secure")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            sev = "MEDIUM" if ("HttpOnly" in missing or "Secure" in missing) else "LOW"
            out.append(wrap_finding(
                f"Session cookie '{name}' missing flag(s): {', '.join(missing)}",
                sev, cvss=("5.3" if sev == "MEDIUM" else "3.1"),
                cwe="CWE-1004", owasp="A05:2021",
                remediation="Set HttpOnly (blocks JS/XSS cookie theft), Secure (HTTPS-only "
                            "transmission), and SameSite=Lax/Strict (CSRF defense) on every "
                            "session/auth cookie.",
                evidence_marker=f"Set-Cookie: {sc[:160]}"))
    return out


def _do_scan(req: ScanRequest) -> dict:
    base = _base(req.target)
    login = _discover_login(req, base)
    if not login:
        return standard_response(
            tool="login_discovery_audit", target=req.target, findings=[],
            tests_performed=len(_LOGIN_PATHS), vulnerable=False,
            skipped_reason=(f"No login endpoint auto-discovered (tried {len(_LOGIN_PATHS)} "
                            "common paths). Supply options.login_url to test a custom path."))

    path, mech = login["path"], login["mech"]
    findings = [wrap_finding(
        f"Login endpoint discovered: {path} ({mech})",
        "INFO", cwe="CWE-287", owasp="A07:2021",
        remediation="Informational — this is the authentication entry point the checks below "
                    "target. The other auth_attacks tiers can be pointed here.",
        evidence_marker=f"POST {base}{path} -> HTTP {login['status']} ({mech} body)")]
    tests = len(_LOGIN_PATHS)

    rl = _check_rate_limit(req, base, path, mech); tests += rl["n"]
    if rl["throttled"]:
        findings.append(wrap_finding(
            "Login endpoint enforces rate-limiting / lockout",
            "POSITIVE", cwe="CWE-307", owasp="A07:2021",
            remediation="No action — throttling/lockout is present.",
            evidence_marker=rl["evidence"]))
    else:
        findings.append(wrap_finding(
            "No rate-limiting or account lockout on the login endpoint",
            "MEDIUM", cvss="5.3", cwe="CWE-307", owasp="A07:2021",
            remediation="Add per-account AND per-IP rate-limiting plus progressive backoff / "
                        "temporary lockout on repeated failures, so credential-stuffing and "
                        "brute-force are not viable. Add CAPTCHA after N failures and alert on "
                        "login bursts.",
            evidence_marker=rl["evidence"]))

    en = _check_enum(req, base, path, mech); tests += en["n"]
    if en["enumerable"]:
        findings.append(wrap_finding(
            "Username / account enumeration via login responses",
            "MEDIUM", cvss="5.3", cwe="CWE-204", owasp="A07:2021",
            remediation="Return an identical generic error and comparable timing for both "
                        "unknown accounts and wrong passwords (e.g. 'invalid email or "
                        "password'). Never reveal 'user not found' vs 'wrong password'.",
            evidence_marker=en["evidence"]))
    elif en["tested"]:
        findings.append(wrap_finding(
            "Login does not obviously enumerate accounts",
            "POSITIVE", cwe="CWE-204", owasp="A07:2021",
            remediation="No action — responses for unknown vs known users were equivalent.",
            evidence_marker=en["evidence"]))

    findings.extend(_check_cookie_flags(req, base, login)); tests += 1

    j = login.get("jwt")
    if j:
        findings.append(wrap_finding(
            f"JWT-based authentication detected (alg={j.get('alg')})",
            "INFO", cwe="CWE-287", owasp="A07:2021",
            remediation="JWT in use. Capture a valid token and run jwt_secret_audit to test "
                        "for weak HMAC secrets, alg=none acceptance, and RS->HS confusion.",
            evidence_marker=f"alg={j.get('alg')} typ={j.get('typ')} claims={j.get('claims')}"))

    graded = any(f.get("severity") in ("MEDIUM", "HIGH", "CRITICAL") for f in findings)
    return standard_response(
        tool="login_discovery_audit", target=req.target, findings=findings,
        tests_performed=tests, vulnerable=graded,
        tests_summary=f"login {path} ({mech}): rate-limit, enumeration, cookie flags, JWT")


class LoginDiscoveryAuditRequest(ScanRequest):
    options: Optional[dict] = None


@router.post("/api/auth_attacks/login_discovery_audit")
async def auth_attacks_login_discovery_audit(req: LoginDiscoveryAuditRequest,
                                             _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="login_discovery_audit", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
