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
    """Pick the session cookie out of a jar - session-pattern names only.

    Zero-FP: do NOT fall back to "the first cookie". A tracking / analytics /
    CSRF / consent cookie must never be mistaken for the session identifier -
    that would let rotation/fixation be graded against the wrong cookie.
    If no session-like name matches, return None and let rule_no_session_cookie
    handle it (and the customer can pass options.session_cookie_name).
    """
    if hint and hint in cookies:
        return hint
    for name in cookies.keys():
        if _SESSION_NAME_PATTERN.search(name):
            return name
    return None


# Redirect Location values that mean "login did NOT succeed" - bounced back to
# an auth challenge rather than into the authenticated app.
_AUTH_BOUNCE_PATTERN = re.compile(
    r"(/login|/signin|/sign-in|/auth|/sso|/mfa|/2fa|/otp|/verify|/challenge|"
    r"error|failed|denied|invalid)",
    re.IGNORECASE,
)


def _looks_protected_redirect(location: str, login_url: str) -> bool:
    """A post-login 302 only proves success if it points AWAY from the login
    page / any auth-challenge - i.e. into the authenticated app."""
    if not location:
        return False
    loc = location.strip()
    if not loc:
        return False
    # A redirect back to (essentially) the same login URL is not a success.
    try:
        from urllib.parse import urljoin, urlparse
        abs_loc = urljoin(login_url, loc)
        lp = urlparse(abs_loc)
        up = urlparse(login_url)
        # Same path as the login page => bounced back to login, not authed.
        if lp.path and up.path and lp.path.rstrip("/") == up.path.rstrip("/"):
            return False
    except Exception:
        pass
    if _AUTH_BOUNCE_PATTERN.search(loc):
        return False
    return True


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
    baseline_marker = False
    protected_redirect = False

    async with httpx.AsyncClient(verify=False, timeout=DEFAULT_TIMEOUT,
                                 follow_redirects=True) as client:
        # Step 1 - GET login page, capture pre-auth session cookie(s).
        # This unauthenticated response is ALSO our baseline: if the
        # success_marker is already present here (catch-all / SPA returns the
        # same "logout"/"dashboard" shell to everyone), the marker proves
        # nothing post-login.
        try:
            r1 = await client.get(url)
            pre_cookies = dict(client.cookies)
            ctx.state["sf_pre_status"] = r1.status_code
            baseline_marker = success_marker in (r1.text or "").lower()
        except Exception as e:
            ctx.state["sf_error"] = f"pre-login GET failed: {e}"
            ctx.source(f"pre-login fetch failed: {e}")
            return

        # Step 2 - POST credentials, keep the same client (cookies persist).
        # Use follow_redirects=False so we can inspect the raw Location header
        # of the login response and judge whether it points into the app.
        post_data = {username_field: username, password_field: password}
        post_data.update({k: str(v) for k, v in extra_fields.items()})
        try:
            r2 = await client.post(url, data=post_data, follow_redirects=False)
            post_status = r2.status_code
            post_location = r2.headers.get("location") or ""
            ctx.state["sf_post_status"] = post_status
            ctx.state["sf_post_location"] = post_location[:300]

            # Marker only counts as a real signal if it appears AFTER auth and
            # did NOT already appear in the unauthenticated baseline (a catch-all
            # shell shows the same "logout"/"dashboard" text to everyone).
            if 300 <= post_status < 400:
                # A 30x redirect carries no body; judge the Location target and,
                # if it points into the protected app, follow it once to read the
                # landing page for the marker.
                protected_redirect = _looks_protected_redirect(post_location, url)
                if protected_redirect:
                    try:
                        from urllib.parse import urljoin
                        r3 = await client.get(urljoin(url, post_location))
                        body_marker = (success_marker in (r3.text or "").lower()
                                       and not baseline_marker)
                    except Exception:
                        pass
            else:
                # Non-redirect (200/4xx/5xx): evaluate the marker on the direct
                # body; a 4xx/5xx body almost never carries the success marker.
                body_marker = (success_marker in (r2.text or "").lower()
                               and not baseline_marker)

            post_cookies = dict(client.cookies)

            # Zero-FP login-success gate: status alone is NEVER proof (a
            # catch-all returns 200/302 to everything). Require a REAL signal:
            #   - a post-auth marker that the unauthenticated baseline lacked, OR
            #   - a redirect whose Location points into a protected area
            #     (away from the login page / any auth challenge).
            login_worked = bool(body_marker or protected_redirect)
        except Exception as e:
            ctx.state["sf_error"] = f"login POST failed: {e}"
            ctx.source(f"login POST failed: {e}")
            return

    # Compare pre/post for the chosen session cookie
    session_name = _detect_session_cookie(pre_cookies, cookie_hint) \
                   or _detect_session_cookie(post_cookies, cookie_hint)

    ctx.state["sf_login_worked"] = login_worked
    ctx.state["sf_body_marker_present"] = body_marker
    ctx.state["sf_baseline_marker_present"] = baseline_marker
    ctx.state["sf_protected_redirect"] = protected_redirect
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
    ("Post-login redirect",         "sf_post_location"),
    ("Login marker present",        "sf_body_marker_present"),
    ("Baseline marker present",     "sf_baseline_marker_present"),
    ("Protected redirect observed", "sf_protected_redirect"),
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
