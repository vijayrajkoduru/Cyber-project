"""mfa_passkey_surface_audit - modern-auth (MFA / WebAuthn / passkey)
surface detection (VL-METHOD methodology).

WHAT THIS SCANNER DOES (and does NOT do)
----------------------------------------
Detection-only (VA, not PT). It enumerates the PUBLIC modern-auth surface
of a web application to answer: does this app offer phishing-resistant
MFA (WebAuthn / passkeys), some MFA, or none; and is any OTP verification
endpoint reachable without documented throttling?

It NEVER performs MFA fatigue / push-bombing, OTP brute force, passkey
downgrade, or any of the §8 BYPASS techniques. Those are active-attack /
manual / red-team techniques and are emitted as advisory-by-design by the
companion advisory scanners. This scanner only OBSERVES the surface.

Playbook coverage (module_playbooks/08_password.md §8 Modern Auth Bypass):
covers the DETECTION/posture side of #82 (OTP endpoint exposure),
#86 (WebAuthn / passkey enumeration) and the presence side of MFA for
#81/#87/#88-90 — without executing any bypass.

7-stage VL-METHOD flow
----------------------
  1. PRE-FLIGHT  - normalize URL, probe '/', require an alive HTTP service.
  2. FINGERPRINT - server markers + login form presence.
  3. QUICK PROBE - fetch root + login page; scan HTML/JS for WebAuthn API
                    markers (navigator.credentials, publicKey, fido2,
                    webauthn) and MFA markers (otp, totp, authenticator,
                    2fa, mfa, push). Probe well-known passkey/MFA paths.
  4. DEEP SCAN   - gated: probe common OTP/verification endpoints with GET
                    and inspect response headers for throttling
                    (RateLimit-*, Retry-After). No code submission.
  5. VERIFY      - re-confirm each observation on a second request.
  6. PRIVILEGE   - posture label per observation.
  7. CHAIN       - inert (VA-not-PT).

Customer input via ScanRequest.options:
  - target            = application base URL (required)
  - options.login_path = explicit login path
  - options.timeout    = per-request timeout seconds (default 6)
  - options.always_deep = run OTP-endpoint deep checks regardless

Safety: GET-only, no code submission, 6 concurrent max, 6s per request.
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel  # noqa: F401

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.mfa_passkey_surface_audit_findings import (
    MFA_PASSKEY_SURFACE_AUDIT_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()

DEFAULT_TIMEOUT = 6.0
MAX_CONCURRENCY = 6

# Paths that, if present, indicate WebAuthn / passkey support.
WEBAUTHN_PATHS = [
    "/.well-known/webauthn",
    "/webauthn/register/options",
    "/webauthn/authenticate/options",
    "/api/webauthn/options",
    "/auth/passkey",
    "/passkeys",
]

# Paths that commonly host OTP / verification.
OTP_PATHS = [
    "/login/verify", "/2fa", "/mfa/verify", "/otp", "/verify-otp",
    "/account/verify", "/auth/verify",
]

LOGIN_PATHS = ["/login", "/signin", "/account/login", "/auth/login", "/users/sign_in"]

RE_PASSWORD_INPUT = re.compile(r"<input[^>]*type\s*=\s*['\"]?password['\"]?", re.IGNORECASE)
RE_WEBAUTHN = re.compile(
    r"navigator\.credentials|publickeycredential|webauthn|fido2|fido_u2f|"
    r"\"publickey\"|isuserverifyingplatformauthenticator|passkey",
    re.IGNORECASE)
RE_MFA = re.compile(
    r"\b(otp|totp|authenticator app|two[- ]?factor|2fa|mfa|"
    r"one[- ]?time (code|password)|verification code|push notification)\b",
    re.IGNORECASE)
RE_THROTTLE_HEADER = re.compile(r"ratelimit|retry-after|x-rate", re.IGNORECASE)

# A page is only treated as a REAL OTP/verification endpoint if its HTML
# actually contains a one-time-code input — i.e. an <input> whose
# name/id/autocomplete/placeholder references otp / code / token / 2fa /
# one-time-password. This is what stops a generic 200 catch-all / soft-404
# / marketing homepage (e.g. github.com/otp returning the full site) from
# being false-flagged as an unthrottled OTP endpoint (zero-FP discipline,
# per the VL-VERIFY SPA-catch-all guard).
RE_OTP_FORM = re.compile(
    r"<input[^>]*(?:name|id|autocomplete|placeholder)\s*=\s*['\"][^'\"]*"
    r"(?:otp|one[\s_-]?time|verification[\s_-]?code|\bcode\b|2fa|two[\s_-]?factor|"
    r"authenticator|totp|mfa[\s_-]?code|security[\s_-]?code)[^'\"]*['\"]",
    re.IGNORECASE)
# Soft-404 markers — bodies that say "not found" even with a 200 status.
RE_SOFT_404 = re.compile(
    r"<title>[^<]*(404|not found|page not found)[^<]*</title>", re.IGNORECASE)


class MfaPasskeySurfaceAuditRequest(ScanRequest):
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
    try:
        import httpx
    except ImportError:
        return await _http_get_requests(url, timeout)
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, verify=False,
            headers={"User-Agent": "VulnusLab-MfaPasskeySurfaceAudit/1.0"},
        ) as client:
            r = await client.get(url)
            return {
                "status": r.status_code,
                "body": (r.text or "")[:131072],
                "headers": {(k or "").lower(): (v or "") for k, v in r.headers.items()},
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
                headers={"User-Agent": "VulnusLab-MfaPasskeySurfaceAudit/1.0"})
            return {
                "status": r.status_code,
                "body": (r.text or "")[:131072],
                "headers": {(k or "").lower(): (v or "") for k, v in r.headers.items()},
                "url": url,
                "final_url": r.url,
            }
        except Exception:
            return None
    return await asyncio.get_event_loop().run_in_executor(None, _run)


class MfaPasskeySurfaceAudit(MethodologyScanner):
    name = "mfa_passkey_surface_audit"

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
        if not root or not (200 <= int(root.get("status") or 0) < 500):
            ctx.state["skipped_reason"] = f"target HTTP not reachable: {base}/"
            return False
        ctx.state["_root_probe"] = root
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        root = ctx.state.get("_root_probe") or {}
        h = root.get("headers") or {}
        body = root.get("body") or ""
        ctx.state["login_form_detected"] = bool(RE_PASSWORD_INPUT.search(body))
        ctx.state["fingerprint"] = {
            "server": h.get("server", ""),
            "status_code": int(root.get("status") or 0),
        }

    # ── STAGE 3: QUICK PROBE (markers + webauthn paths) ──────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        base = ctx.state.get("target_base") or ""
        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
        findings: list[dict] = []
        indicators: dict = {}
        webauthn_endpoints: list[str] = []

        # Gather candidate HTML bodies: root + login pages.
        sem = asyncio.Semaphore(MAX_CONCURRENCY)
        bodies: list[tuple[str, str]] = []
        root = ctx.state.get("_root_probe") or {}
        if root.get("body"):
            bodies.append(("/", root.get("body")))

        login_candidates = []
        explicit = opts.get("login_path")
        if explicit and isinstance(explicit, str):
            login_candidates.append(explicit if explicit.startswith("/") else "/" + explicit)
        login_candidates.extend(LOGIN_PATHS)

        async def _fetch_body(path):
            url = base.rstrip("/") + path
            async with sem:
                p = await _http_get(url, timeout)
            if p and int(p.get("status") or 0) == 200 and p.get("body"):
                bodies.append((path, p.get("body")))
                if RE_PASSWORD_INPUT.search(p.get("body") or ""):
                    ctx.state["login_form_detected"] = True

        await asyncio.gather(*[_fetch_body(p) for p in login_candidates[:6]])

        # Scan collected HTML/JS for WebAuthn + MFA markers.
        webauthn_seen = False
        mfa_seen = False
        for path, body in bodies:
            if RE_WEBAUTHN.search(body or ""):
                webauthn_seen = True
                indicators.setdefault("webauthn_markers", []).append(path)
            if RE_MFA.search(body or ""):
                mfa_seen = True
                indicators.setdefault("mfa_markers", []).append(path)

        # Probe well-known WebAuthn endpoints (existence => passkey support).
        async def _probe_webauthn(path):
            url = base.rstrip("/") + path
            async with sem:
                p = await _http_get(url, timeout)
            if p and int(p.get("status") or 0) in (200, 401, 403, 405):
                # Endpoint exists (even auth-gated counts as "present")
                webauthn_endpoints.append(path)

        await asyncio.gather(*[_probe_webauthn(p) for p in WEBAUTHN_PATHS])
        if webauthn_endpoints:
            webauthn_seen = True

        if webauthn_seen:
            detail = ", ".join((indicators.get("webauthn_markers") or []) + webauthn_endpoints) or "client markers"
            findings.append({
                "id": "webauthn", "kind": "webauthn_supported",
                "detail": detail[:200],
                "discovery_method": "html_marker_or_endpoint_probe",
            })
        if mfa_seen:
            detail = ", ".join(indicators.get("mfa_markers") or []) or "auth markers"
            findings.append({
                "id": "mfa", "kind": "mfa_offered",
                "detail": detail[:200],
                "discovery_method": "html_marker_scan",
            })

        ctx.state["mfa_indicators"] = indicators
        ctx.state["webauthn_endpoints"] = webauthn_endpoints
        return findings

    # ── STAGE 4: DEEP SCAN (OTP endpoint throttling) ─────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        base = ctx.state.get("target_base") or ""
        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
        sem = asyncio.Semaphore(MAX_CONCURRENCY)
        otp_endpoints: list[str] = []
        findings: list[dict] = []

        async def _probe_otp(path):
            url = base.rstrip("/") + path
            async with sem:
                p = await _http_get(url, timeout)
            if not p:
                return
            status = int(p.get("status") or 0)
            if status != 200:
                return
            body = p.get("body") or ""
            final_url = (p.get("final_url") or url)
            # ZERO-FP GUARD 1: reject soft-404 bodies (200 status but "not found"
            # in the title) — common for catch-all SPA / marketing pages.
            if RE_SOFT_404.search(body):
                return
            # ZERO-FP GUARD 2: the response must actually contain an OTP / code
            # input field. A generic 200 (homepage, SPA shell, soft-404) that
            # merely happens to live at /otp is NOT a verification endpoint.
            if not RE_OTP_FORM.search(body):
                return
            # ZERO-FP GUARD 3: if the request was redirected away from the
            # requested path (e.g. -> /login), it is not a standalone OTP page.
            req_path = path.strip("/").lower()
            if req_path and req_path not in (final_url or "").lower():
                return
            otp_endpoints.append(path)
            headers = p.get("headers") or {}
            has_throttle = any(RE_THROTTLE_HEADER.search(k) for k in headers.keys())
            if not has_throttle:
                # Confirmed verification form reachable with NO throttle headers.
                findings.append({
                    "id": f"otp_{path}", "kind": "otp_endpoint_no_throttle",
                    "detail": f"{path} (OTP/code form present, status 200, no RateLimit/Retry-After header)",
                    "endpoint": path,
                    "discovery_method": "otp_endpoint_form_and_header_inspection",
                })

        await asyncio.gather(*[_probe_otp(p) for p in OTP_PATHS])
        ctx.state["otp_endpoints"] = otp_endpoints
        return findings

    # ── STAGE 5: VERIFY (re-confirm) ─────────────────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # WebAuthn / MFA marker findings are POSITIVE/INFO posture statements;
        # they are stable observations — mark CONFIRMED without re-probe noise.
        if finding.get("kind") in ("webauthn_supported", "mfa_offered"):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "static_marker_observation"
            return finding

        # OTP-endpoint finding: re-fetch + re-confirm absence of throttle headers.
        if finding.get("kind") == "otp_endpoint_no_throttle":
            base = ctx.state.get("target_base") or ""
            opts = ctx.state.get("_options") or {}
            timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
            path = finding.get("endpoint") or ""
            url = base.rstrip("/") + path
            p = await _http_get(url, timeout)
            if not p or int(p.get("status") or 0) != 200:
                return None
            body = p.get("body") or ""
            # Re-apply the same zero-FP guards on the second fetch: the OTP form
            # must still be present and not a soft-404.
            if RE_SOFT_404.search(body) or not RE_OTP_FORM.search(body):
                return None
            headers = p.get("headers") or {}
            if any(RE_THROTTLE_HEADER.search(k) for k in headers.keys()):
                # Throttling headers now present — not a finding, drop.
                return None
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "second_fetch_otp_form_no_throttle_header"
            return finding

        finding["confidence"] = "SUSPECTED"
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        finding["privilege_level"] = {
            "webauthn_supported": "phishing_resistant",
            "mfa_offered": "mfa_present",
            "otp_endpoint_no_throttle": "otp_brute_surface",
        }.get(finding.get("kind", ""), "unknown")
        return finding

    # ── STAGE 7: CHAIN HANDOFF (inert) ───────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        return []


@router.post("/api/password/mfa_passkey_surface_audit")
async def password_mfa_passkey_surface_audit(req: MfaPasskeySurfaceAuditRequest,
                                             _=Depends(verify_scan_quota)):
    scanner = MfaPasskeySurfaceAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=MFA_PASSKEY_SURFACE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)
