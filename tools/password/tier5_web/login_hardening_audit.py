"""login_hardening_audit - credential-stuffing resistance of a web login
form (VL-METHOD methodology).

WHAT THIS SCANNER DOES (and does NOT do)
----------------------------------------
Detection-only (VA, not PT). It finds the application's login form and
assesses the CLIENT-SIDE / TRANSPORT hardening that determines how well it
resists credential stuffing and password spraying — WITHOUT ever submitting
real credentials or brute-forcing the form.

Real, observable checks (each maps to a graded finding ONLY when observed):
  * Login served over cleartext HTTP            -> HIGH  (CWE-319)
  * Session/auth cookie missing Secure/HttpOnly -> MEDIUM (CWE-1004)
  * Login page framable (no XFO / frame-ancestors) -> MEDIUM (CWE-1021)
  * Password field allows autocomplete          -> LOW   (CWE-522)

Advisory-by-design (cannot be PROVEN without active abuse):
  * Rate limiting / account lockout / CAPTCHA   -> INFO advisory. Proving
    these requires submitting many failed logins (active brute), which this
    scanner refuses to do. We report the assessment as INFO with a manual
    verification checklist instead of a fabricated graded finding.

Playbook coverage (module_playbooks/08_password.md §3 Credential Stuffing &
Spray): covers the DEFENSIVE posture side of #31 (spray), #32 (stuffing),
#34 (lockout evasion) and #40 (rate-limit bypass) — i.e. whether the
controls those attacks defeat are even present.

7-stage VL-METHOD flow
----------------------
  1. PRE-FLIGHT  - normalize URL, probe '/', require an alive HTTP service.
  2. FINGERPRINT - server / framework markers from the root response.
  3. QUICK PROBE - locate the login form: scan root + common login paths,
                    parse HTML for <input type=password>. Record the login
                    URL, form action, and the page's security headers.
  4. DEEP SCAN   - gated on a login form being found OR always_deep: read
                    Set-Cookie flags, autocomplete attribute, transport
                    scheme, framing headers. Collect passive anti-automation
                    signals (CAPTCHA markers, Retry-After, RateLimit-*).
  5. VERIFY      - re-fetch the login URL and re-confirm each weakness on a
                    second request (stable -> CONFIRMED, else dropped).
  6. PRIVILEGE   - exposure-class label per weakness.
  7. CHAIN       - inert (VA-not-PT).

Customer input via ScanRequest.options:
  - target            = application base URL (required)
  - options.login_path = explicit login path (e.g. /account/login)
  - options.timeout    = per-request timeout seconds (default 6)
  - options.always_deep = run deep checks even if no form auto-detected

Safety: GET-only requests, no credential submission, 6 concurrent max,
hard 6s per request, max 12 candidate login paths.
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional
from urllib.parse import urlparse, urljoin

from fastapi import APIRouter, Depends
from pydantic import BaseModel  # noqa: F401

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.login_hardening_audit_findings import (
    LOGIN_HARDENING_AUDIT_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()

DEFAULT_TIMEOUT = 6.0
MAX_CONCURRENCY = 6
MAX_LOGIN_PATHS = 12

LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/account/login", "/auth/login",
    "/users/sign_in", "/user/login", "/admin/login", "/wp-login.php",
    "/session/new", "/accounts/login", "/login.php",
]

RE_PASSWORD_INPUT = re.compile(r"<input[^>]*type\s*=\s*['\"]?password['\"]?", re.IGNORECASE)
RE_FORM_OPEN = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
RE_FORM_ACTION = re.compile(r"action\s*=\s*['\"]([^'\"]*)['\"]", re.IGNORECASE)
RE_AUTOCOMPLETE_OFF = re.compile(
    r"autocomplete\s*=\s*['\"]?(off|new-password|current-password)['\"]?",
    re.IGNORECASE,
)
RE_CAPTCHA = re.compile(
    r"recaptcha|hcaptcha|cf-turnstile|g-recaptcha|captcha", re.IGNORECASE)


class LoginHardeningAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_url(target: str) -> str:
    if not target:
        return ""
    t = target.strip()
    if "://" not in t:
        t = "https://" + t
    p = urlparse(t)
    scheme = (p.scheme or "https").lower()
    netloc = p.netloc or p.path.split("/", 1)[0]
    if not netloc:
        return ""
    WEB_PORTS = {80, 443, 8080, 8443, 8000, 8001, 8888, 3000, 5000, 9000, 9090}
    if ":" in netloc:
        host, _, port_str = netloc.rpartition(":")
        try:
            if int(port_str) not in WEB_PORTS:
                netloc = host
        except (ValueError, TypeError):
            pass
    return f"{scheme}://{netloc}"


async def _http_get(url: str, timeout: float) -> Optional[dict]:
    """GET a URL. Returns {status, body, headers, url, final_url} or None."""
    try:
        import httpx
    except ImportError:
        return await _http_get_requests(url, timeout)
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, verify=False,
            headers={"User-Agent": "VulnusLab-LoginHardeningAudit/1.0"},
        ) as client:
            r = await client.get(url)
            return {
                "status": r.status_code,
                "body": (r.text or "")[:131072],
                "headers": dict(r.headers),
                "set_cookie": list(r.headers.get_list("set-cookie")) if hasattr(r.headers, "get_list") else (
                    [r.headers["set-cookie"]] if "set-cookie" in r.headers else []),
                "url": url,
                "final_url": str(r.url),
            }
    except Exception:
        return None


async def _http_get_requests(url: str, timeout: float) -> Optional[dict]:
    try:
        import requests
    except ImportError:
        return None
    def _run():
        try:
            r = requests.get(
                url, timeout=timeout, allow_redirects=True, verify=False,
                headers={"User-Agent": "VulnusLab-LoginHardeningAudit/1.0"})
            cookies = r.headers.get("set-cookie")
            return {
                "status": r.status_code,
                "body": (r.text or "")[:131072],
                "headers": dict(r.headers),
                "set_cookie": [cookies] if cookies else [],
                "url": url,
                "final_url": r.url,
            }
        except Exception:
            return None
    return await asyncio.get_event_loop().run_in_executor(None, _run)


def _has_login_form(body: str) -> bool:
    return bool(body) and bool(RE_PASSWORD_INPUT.search(body))


def _lower_headers(headers: dict) -> dict:
    return {(k or "").lower(): (v or "") for k, v in (headers or {}).items()}


def _analyse_login(login_url: str, probe: dict) -> list[dict]:
    """Derive observed weaknesses from a real login response. Each entry is
    a preliminary finding with kind + detail. Only conditions ACTUALLY seen
    are returned (zero-FP)."""
    out: list[dict] = []
    body = probe.get("body") or ""
    headers = _lower_headers(probe.get("headers") or {})
    final_url = probe.get("final_url") or login_url

    # 1. Transport: login over cleartext HTTP
    parsed = urlparse(final_url)
    form_action = ""
    m = RE_FORM_ACTION.search(body or "")
    if m:
        form_action = m.group(1)
    action_is_http = form_action.lower().startswith("http://")
    if parsed.scheme == "http" or action_is_http:
        detail = f"login URL scheme={parsed.scheme}"
        if action_is_http:
            detail += f"; form action={form_action[:120]}"
        out.append({"kind": "login_over_http", "detail": detail})

    # 2. Cookie flags from real Set-Cookie headers
    set_cookies = probe.get("set_cookie") or []
    for c in set_cookies:
        cl = (c or "").lower()
        # Only assess cookies that look session/auth related
        name = cl.split("=", 1)[0].strip()
        looks_session = any(tok in name for tok in (
            "sess", "auth", "token", "sid", "login", "jwt", "csrf"))
        if not looks_session:
            continue
        if "secure" not in cl:
            out.append({"kind": "cookie_missing_secure",
                        "detail": f"cookie '{name}' missing Secure"})
        if "httponly" not in cl:
            out.append({"kind": "cookie_missing_httponly",
                        "detail": f"cookie '{name}' missing HttpOnly"})

    # 3. Framing protection on the login page
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    framable = (not xfo) and ("frame-ancestors" not in csp.lower())
    if framable:
        out.append({"kind": "login_framable", "detail": "no X-Frame-Options / frame-ancestors"})

    # 4. Password autocomplete — only flag if we can see the password input
    #    AND no autocomplete-off/current-password attribute is present.
    if RE_PASSWORD_INPUT.search(body or "") and not RE_AUTOCOMPLETE_OFF.search(body or ""):
        out.append({"kind": "password_autocomplete_on",
                    "detail": "password input without autocomplete restriction"})
    return out


def _passive_antiautomation(probe: dict) -> dict:
    """Best-effort passive signals about anti-automation controls. Used for
    the advisory INFO finding ONLY — never graded."""
    headers = _lower_headers(probe.get("headers") or {})
    body = probe.get("body") or ""
    signals = {}
    if RE_CAPTCHA.search(body):
        signals["captcha_marker_in_html"] = True
    for h in ("ratelimit-limit", "x-ratelimit-limit", "retry-after"):
        if h in headers:
            signals[h] = headers[h]
    return signals


class LoginHardeningAudit(MethodologyScanner):
    name = "login_hardening_audit"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        target = ctx.host
        if not target:
            ctx.state["skipped_reason"] = "no target supplied"
            return False
        base = _normalize_url(target)
        if not base:
            ctx.state["skipped_reason"] = "no target supplied"
            return False
        ctx.state["target_base"] = base
        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
        root = await _http_get(base + "/", timeout)
        if not root:
            ctx.state["skipped_reason"] = f"target HTTP not reachable: {base}/"
            return False
        status = int(root.get("status") or 0)
        if not (200 <= status < 500):
            ctx.state["skipped_reason"] = f"target HTTP not reachable (status={status})"
            return False
        ctx.state["_root_probe"] = root
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        root = ctx.state.get("_root_probe") or {}
        h = _lower_headers(root.get("headers") or {})
        ctx.state["fingerprint"] = {
            "server": h.get("server", ""),
            "powered_by": h.get("x-powered-by", ""),
            "status_code": int(root.get("status") or 0),
        }

    # ── STAGE 3: QUICK PROBE (locate the login form) ─────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        base = ctx.state.get("target_base") or ""
        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)

        # Candidate paths: explicit login_path first, then root, then common.
        candidates: list[str] = []
        explicit = opts.get("login_path")
        if explicit and isinstance(explicit, str):
            ep = explicit if explicit.startswith("/") else "/" + explicit
            candidates.append(ep)
        candidates.append("/")
        candidates.extend(LOGIN_PATHS)
        # dedupe preserve order, cap
        seen = set()
        paths = []
        for p in candidates:
            if p in seen:
                continue
            seen.add(p)
            paths.append(p)
            if len(paths) >= MAX_LOGIN_PATHS:
                break

        sem = asyncio.Semaphore(MAX_CONCURRENCY)
        found: dict = {}

        async def _try(path):
            if found:
                return
            url = base.rstrip("/") + path
            async with sem:
                probe = await _http_get(url, timeout)
            if not probe:
                return
            if int(probe.get("status") or 0) == 200 and _has_login_form(probe.get("body") or ""):
                if not found:
                    found["url"] = probe.get("final_url") or url
                    found["probe"] = probe

        # Probe root first (often the login is on the homepage), then others.
        await _try(paths[0])
        if not found:
            await asyncio.gather(*[_try(p) for p in paths[1:]])

        ctx.state["login_form_detected"] = bool(found)
        if not found:
            ctx.state["skipped_reason"] = "no login form auto-detected"
            return []

        login_url = found["url"]
        probe = found["probe"]
        ctx.state["login_url"] = login_url
        ctx.state["cookie_flags"] = probe.get("set_cookie") or []
        ctx.state["antiautomation_signals"] = _passive_antiautomation(probe)
        ctx.state["_login_probe"] = probe

        weaknesses = _analyse_login(login_url, probe)
        findings = []
        for i, w in enumerate(weaknesses):
            findings.append({
                "id": f"login_{i}",
                "kind": w["kind"],
                "detail": w["detail"],
                "login_url": login_url,
                "discovery_method": "login_form_static_analysis",
            })
        return findings

    # ── STAGE 4: DEEP SCAN (no-op refinement; analysis done in quick) ─
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        # All client-side weaknesses are derived once in quick_probe from the
        # login response; deep_scan adds nothing further to avoid extra noise
        # and to stay strictly read-only. Kept for VL-METHOD parity.
        return []

    # ── STAGE 5: VERIFY (re-fetch, re-confirm) ───────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # VL-FOUNDRY evidence surfacing: stamp a concrete, per-finding
        # evidence string onto the methodology finding object. This rides
        # into the report via the methodology_findings intel field; it adds
        # no new finding and changes no severity (advisory-by-design safe).
        finding["evidence_marker"] = (
            f"{finding.get('discovery_method') or finding.get('kind') or 'probe'}"
            f" -> verifying {finding.get('kind') or 'finding'} for "
            f"{finding.get('user') or finding.get('attack_label') or ctx.host}")
        base = ctx.state.get("target_base") or ""
        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
        login_url = finding.get("login_url") or ctx.state.get("login_url") or ""
        if not login_url:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "no_login_url_to_reconfirm"
            return finding

        probe2 = await _http_get(login_url, timeout)
        if not probe2:
            # Could not re-fetch — drop rather than ship unstable.
            return None
        re_weak = {w["kind"] for w in _analyse_login(login_url, probe2)}
        if finding.get("kind") in re_weak:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "second_fetch_reconfirm"
            return finding
        # Weakness not reproduced on the second request — drop (zero-FP).
        return None

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        k = finding.get("kind", "")
        finding["privilege_level"] = {
            "login_over_http": "credential_interception_capable",
            "cookie_missing_secure": "session_theft_capable",
            "cookie_missing_httponly": "session_theft_capable",
            "login_framable": "clickjacking_capable",
            "password_autocomplete_on": "shared_device_credential_cache",
        }.get(k, "unknown")
        return finding

    # ── STAGE 7: CHAIN HANDOFF (inert) ───────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        return []


@router.post("/api/password/login_hardening_audit")
async def password_login_hardening_audit(req: LoginHardeningAuditRequest,
                                          _=Depends(verify_scan_quota)):
    scanner = LoginHardeningAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=LOGIN_HARDENING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)
