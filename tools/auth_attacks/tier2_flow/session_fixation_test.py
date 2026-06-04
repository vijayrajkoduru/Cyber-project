"""session_fixation_test - session ID not regenerated after login (playbook §2).

Customer's ScanRequest.target = login URL. The probe runs the canonical
session fixation test:
  1. GET the login page in a fresh client -> capture cookie A (pre-auth session).
  2. POST credentials to ScanRequest.target with cookie A still attached.
  3. If the post-login response keeps cookie A live (no Set-Cookie that
     rotates the session ID), the attacker can pre-set the victim's
     cookie and inherit the authenticated session.

Customer input via ScanRequest.options:
  - target                = login form URL (required)
  - options.username      = valid username (required)
  - options.password      = valid password (required)
  - options.username_field = form field name (default 'username')
  - options.password_field = form field name (default 'password')
  - options.extra_fields  = optional dict of extra POST fields (csrf token etc.)
  - options.session_cookie_name = optional explicit cookie name; auto-detect otherwise
  - options.success_marker = text in response body indicating login worked (default 'logout')

Privacy: the password is NEVER echoed to findings; only the cookie name
and the before/after values (truncated) appear.
"""
from __future__ import annotations
import asyncio
import re
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.session_fixation_test_findings import SESSION_FIXATION_TEST_FINDING_RULES

router = APIRouter()

DEFAULT_TIMEOUT = 15

# Cookie name patterns the auto-detector treats as session identifiers.
_SESSION_NAME_PATTERN = re.compile(
    r"(session|sess|sid|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|laravel_session|"
    r"_session_id|django_session|rack\.session|auth|token|jwt)",
    re.IGNORECASE,
)


class SessionFixationTestRequest(ScanRequest):
    options: Optional[dict] = None


def _detect_session_cookie(cookies: dict, hint: Optional[str]) -> Optional[str]:
    """Pick the most-likely session cookie out of a jar."""
    if hint and hint in cookies:
        return hint
    for name in cookies.keys():
        if _SESSION_NAME_PATTERN.search(name):
            return name
    # Fall back to first cookie - some frameworks use opaque names
    if cookies:
        return list(cookies.keys())[0]
    return None


def _redact_cookie(val: str) -> str:
    if not val:
        return ""
    if len(val) <= 6:
        return f"len={len(val)} ***"
    return f"len={len(val)} {val[:3]}...{val[-3:]}"


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    target = ctx.host  # login URL
    username = opts.get("username")
    password = opts.get("password")
    username_field = opts.get("username_field") or "username"
    password_field = opts.get("password_field") or "password"
    extra_fields = opts.get("extra_fields") or {}
    cookie_hint = opts.get("session_cookie_name")
    success_marker = (opts.get("success_marker") or "logout").lower()

    if not target:
        ctx.state["sf_input_missing"] = True
        ctx.source("no target login URL")
        return
    if not username or not password:
        ctx.state["sf_input_missing"] = True
        ctx.source("missing options.username/password")
        return

    # Normalize target into a full URL
    url = target.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    try:
        import httpx
    except ImportError:
        ctx.state["sf_httpx_missing"] = True
        ctx.source("httpx not installed")
        return

    pre_cookies: dict = {}
    post_cookies: dict = {}
    login_worked = False
    body_marker = False

    async with httpx.AsyncClient(verify=False, timeout=DEFAULT_TIMEOUT,
                                 follow_redirects=True) as client:
        # Step 1 - GET login page, capture pre-auth session cookie(s)
        try:
            r1 = await client.get(url)
            pre_cookies = dict(client.cookies)
            ctx.state["sf_pre_status"] = r1.status_code
        except Exception as e:
            ctx.state["sf_error"] = f"pre-login GET failed: {e}"
            ctx.source(f"pre-login fetch failed: {e}")
            return

        # Step 2 - POST credentials, keep the same client (cookies persist)
        post_data = {username_field: username, password_field: password}
        post_data.update({k: str(v) for k, v in extra_fields.items()})
        try:
            r2 = await client.post(url, data=post_data)
            post_cookies = dict(client.cookies)
            ctx.state["sf_post_status"] = r2.status_code
            body_marker = success_marker in (r2.text or "").lower()
            # Heuristic for login success - either marker present, or post-login
            # response is 200/302 to a different URL than the login page
            login_worked = body_marker or (r2.status_code in (200, 302, 303))
        except Exception as e:
            ctx.state["sf_error"] = f"login POST failed: {e}"
            ctx.source(f"login POST failed: {e}")
            return

    # Compare pre/post for the chosen session cookie
    session_name = _detect_session_cookie(pre_cookies, cookie_hint) \
                   or _detect_session_cookie(post_cookies, cookie_hint)

    ctx.state["sf_login_worked"] = login_worked
    ctx.state["sf_body_marker_present"] = body_marker
    ctx.state["sf_session_cookie_name"] = session_name
    ctx.state["sf_pre_cookies"] = list(pre_cookies.keys())
    ctx.state["sf_post_cookies"] = list(post_cookies.keys())

    if not session_name:
        ctx.state["sf_no_session_cookie"] = True
        ctx.source("no session-looking cookie found in either response")
        return

    pre_val = pre_cookies.get(session_name)
    post_val = post_cookies.get(session_name)
    ctx.state["sf_pre_cookie_redacted"] = _redact_cookie(pre_val or "")
    ctx.state["sf_post_cookie_redacted"] = _redact_cookie(post_val or "")

    fixed = False
    if pre_val and post_val:
        # Same exact value across pre/post = session NOT rotated
        if pre_val == post_val:
            fixed = True

    ctx.state["sf_session_fixed"] = fixed and login_worked
    if fixed and login_worked:
        ctx.source(f"session NOT rotated: cookie {session_name} kept same value after login")
    elif login_worked:
        ctx.source(f"session rotated correctly: cookie {session_name} changed after login")
    else:
        ctx.source("login may have failed; cannot reliably test session rotation")


INTEL_FIELDS = [
    ("Pre-login status",            "sf_pre_status"),
    ("Post-login status",           "sf_post_status"),
    ("Login marker present",        "sf_body_marker_present"),
    ("Session cookie name",         "sf_session_cookie_name"),
    ("Pre-login cookies",           "sf_pre_cookies"),
    ("Post-login cookies",          "sf_post_cookies"),
    ("Pre cookie (redacted)",       "sf_pre_cookie_redacted"),
    ("Post cookie (redacted)",      "sf_post_cookie_redacted"),
]


@router.post("/api/auth_attacks/session_fixation_test")
async def auth_attacks_session_fixation_test(req: SessionFixationTestRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="session_fixation_test",
        gather_func=_gather_with_options,
        finding_rules=SESSION_FIXATION_TEST_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
