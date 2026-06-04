"""mfa_bypass_test - skip MFA step / forge MFA flag / replay (playbook §2 #21).

Customer's ScanRequest.target = identifier (logging only). Probe runs
four real MFA-bypass tests using httpx with a cookie jar:

  (a) Login with creds, get session, attempt to access options.protected_url
      WITHOUT completing the MFA step.
  (b) Modify session cookie to inject mfa_verified=true / mfa=passed signals
      and re-request the protected resource.
  (c) Replay a previously-captured successful MFA response (provided via
      options.mfa_success_body) into the MFA endpoint.
  (d) Skip MFA by directly requesting the protected URL with the post-creds
      session (some apps gate only the login response, not the resource).

Customer input via ScanRequest.options:
  - target                    = identifier (string)
  - options.login_endpoint    = URL of the credential POST (required)
  - options.mfa_endpoint      = URL of the MFA verify POST (required)
  - options.protected_url     = a URL that requires MFA (required)
  - options.test_username     = valid creds (required)
  - options.test_password     = valid creds (required)
  - options.username_field    = form field, default 'username'
  - options.password_field    = form field, default 'password'
  - options.mfa_success_body  = optional captured MFA-success POST body to replay
  - options.protected_marker  = string in protected_url response when MFA passed,
                                default 'mfa-verified' or detect 200 vs 302
  - options.session_cookie_name = optional, auto-detect otherwise
"""
from __future__ import annotations
import asyncio
import json
import re
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.mfa_bypass_test_findings import MFA_BYPASS_TEST_FINDING_RULES

router = APIRouter()

DEFAULT_TIMEOUT = 15

# Common cookie-name heuristics for MFA-flag injection
MFA_FLAG_PATTERNS = [
    ("mfa_verified", "true"),
    ("mfa_passed", "1"),
    ("mfa", "verified"),
    ("step_up", "complete"),
    ("2fa", "passed"),
    ("totp_verified", "true"),
]


class MfaBypassTestRequest(ScanRequest):
    options: Optional[dict] = None


def _response_looks_authed(r, marker: Optional[str]) -> bool:
    """Heuristic: 200 OK + (marker present OR no MFA challenge in body)."""
    if r is None:
        return False
    if r.status_code == 302 or r.status_code == 303:
        loc = (r.headers.get("location") or "").lower()
        # Redirect AWAY from MFA challenge towards a dashboard-like URL
        if any(w in loc for w in ("/login", "/mfa", "/verify", "/2fa", "/challenge")):
            return False
        return True
    if r.status_code != 200:
        return False
    body = (r.text or "")[:5000].lower()
    if marker and marker.lower() in body:
        return True
    # Default heuristic: MFA challenge keywords absent + has 'logout' or similar authed signal
    mfa_words = ("mfa", "two-factor", "2fa", "totp", "authenticator", "verify your", "enter the code")
    if any(w in body for w in mfa_words):
        return False
    if any(w in body for w in ("logout", "sign out", "dashboard", "profile", "settings", "welcome back")):
        return True
    return False


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    login_url = (opts.get("login_endpoint") or "").strip()
    mfa_url = (opts.get("mfa_endpoint") or "").strip()
    protected_url = (opts.get("protected_url") or "").strip()
    username = opts.get("test_username")
    password = opts.get("test_password")
    username_field = opts.get("username_field") or "username"
    password_field = opts.get("password_field") or "password"
    mfa_success_body = opts.get("mfa_success_body")  # dict|str|None
    marker = opts.get("protected_marker")

    if not login_url or not mfa_url or not protected_url or not username or not password:
        ctx.state["mfa_input_missing"] = True
        ctx.source("missing login_endpoint/mfa_endpoint/protected_url/creds")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["mfa_httpx_missing"] = True
        ctx.source("httpx not installed")
        return

    findings: dict = {}

    # ---- helper: spin up a fresh client + complete the login (NOT the MFA) ----
    async def _login_only(client):
        try:
            r1 = await client.post(login_url, data={
                username_field: username,
                password_field: password,
            })
            return r1
        except Exception as e:
            return None

    # ---- (a) Skip MFA: access protected URL with post-login session ----
    try:
        async with httpx.AsyncClient(verify=False, timeout=DEFAULT_TIMEOUT,
                                     follow_redirects=False) as c1:
            r_login = await _login_only(c1)
            login_status = r_login.status_code if r_login else 0
            ctx.state["mfa_login_status"] = login_status
            ctx.state["mfa_login_cookies"] = list(c1.cookies.keys())
            # Now go straight to protected_url
            try:
                r_prot = await c1.get(protected_url, follow_redirects=False)
                bypass_a = _response_looks_authed(r_prot, marker)
                ctx.state["mfa_skip_step_status"] = r_prot.status_code
                ctx.state["mfa_skip_step_accepted"] = bypass_a
                if bypass_a:
                    findings.setdefault("accepted", []).append("skip_mfa_step")
            except Exception as e:
                ctx.state["mfa_skip_step_error"] = str(e)[:200]
    except Exception as e:
        ctx.state["mfa_login_error"] = str(e)[:200]

    # ---- (b) Forge mfa_verified cookie flag ----
    try:
        async with httpx.AsyncClient(verify=False, timeout=DEFAULT_TIMEOUT,
                                     follow_redirects=False) as c2:
            await _login_only(c2)
            forged_results = []
            for flag_name, flag_val in MFA_FLAG_PATTERNS:
                # Set the forged flag onto the cookie jar
                domain = urlparse(protected_url).hostname or ""
                try:
                    c2.cookies.set(flag_name, flag_val, domain=domain)
                except Exception:
                    c2.cookies.set(flag_name, flag_val)
                try:
                    r = await c2.get(protected_url, follow_redirects=False)
                    accepted = _response_looks_authed(r, marker)
                    forged_results.append({
                        "flag":     f"{flag_name}={flag_val}",
                        "status":   r.status_code,
                        "accepted": accepted,
                    })
                    if accepted:
                        findings.setdefault("accepted", []).append(f"forged_cookie:{flag_name}")
                except Exception as e:
                    forged_results.append({
                        "flag":   f"{flag_name}={flag_val}",
                        "error":  str(e)[:120],
                        "accepted": False,
                    })
            ctx.state["mfa_forged_cookie_results"] = forged_results
    except Exception as e:
        ctx.state["mfa_forge_error"] = str(e)[:200]

    # ---- (c) Replay a known-good MFA success body ----
    if mfa_success_body:
        try:
            async with httpx.AsyncClient(verify=False, timeout=DEFAULT_TIMEOUT,
                                         follow_redirects=False) as c3:
                await _login_only(c3)
                try:
                    if isinstance(mfa_success_body, dict):
                        post_data = mfa_success_body
                        r_mfa = await c3.post(mfa_url, data=post_data)
                    else:
                        # Treat as raw form-encoded string OR json
                        body_str = str(mfa_success_body)
                        if body_str.strip().startswith("{"):
                            r_mfa = await c3.post(mfa_url, json=json.loads(body_str))
                        else:
                            r_mfa = await c3.post(mfa_url, content=body_str.encode(),
                                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
                    # Now try the protected resource
                    r_prot = await c3.get(protected_url, follow_redirects=False)
                    accepted = _response_looks_authed(r_prot, marker)
                    ctx.state["mfa_replay_status"] = r_mfa.status_code
                    ctx.state["mfa_replay_protected_status"] = r_prot.status_code
                    ctx.state["mfa_replay_accepted"] = accepted
                    if accepted:
                        findings.setdefault("accepted", []).append("replay_success_body")
                except Exception as e:
                    ctx.state["mfa_replay_error"] = str(e)[:200]
        except Exception as e:
            ctx.state["mfa_replay_outer_error"] = str(e)[:200]
    else:
        ctx.state["mfa_replay_skipped"] = True

    # ---- (d) Direct protected URL (no login at all) — sanity baseline ----
    try:
        async with httpx.AsyncClient(verify=False, timeout=DEFAULT_TIMEOUT,
                                     follow_redirects=False) as c4:
            r = await c4.get(protected_url, follow_redirects=False)
            ctx.state["mfa_unauth_baseline_status"] = r.status_code
            # If unauth GET returns 200 + dashboard, the resource isn't authed at all
            if _response_looks_authed(r, marker):
                ctx.state["mfa_protected_url_not_actually_protected"] = True
                findings.setdefault("accepted", []).append("protected_url_unauth_open")
    except Exception as e:
        ctx.state["mfa_baseline_error"] = str(e)[:200]

    accepted = findings.get("accepted") or []
    ctx.state["mfa_bypass_modes"] = accepted
    ctx.source(f"4 MFA-bypass tests run, {len(accepted)} succeeded")


INTEL_FIELDS = [
    ("Login response status",           "mfa_login_status"),
    ("Login cookies set",               "mfa_login_cookies"),
    ("Skip-MFA-step status",            "mfa_skip_step_status"),
    ("Skip-MFA-step accepted",          "mfa_skip_step_accepted"),
    ("Forged cookie results",           "mfa_forged_cookie_results"),
    ("MFA replay status",               "mfa_replay_status"),
    ("MFA replay protected status",     "mfa_replay_protected_status"),
    ("MFA replay accepted",             "mfa_replay_accepted"),
    ("Unauth baseline status",          "mfa_unauth_baseline_status"),
    ("Bypass modes succeeded",          "mfa_bypass_modes"),
]


@router.post("/api/auth_attacks/mfa_bypass_test")
async def auth_attacks_mfa_bypass_test(req: MfaBypassTestRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="mfa_bypass_test",
        gather_func=_gather_with_options,
        finding_rules=MFA_BYPASS_TEST_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
