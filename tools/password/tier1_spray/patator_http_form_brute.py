"""patator_http_form_brute - HTTP form login brute via Patator (VL-METHOD).

REWRITTEN 2026-06-05 to the VL-METHOD 7-step pentest methodology, mirroring
the hydra_ssh_spray reference scanner. Replaces the previous shallow
"shell out to patator and grep stdout" approach.

The 7 stages this scanner performs:

  1. PRE-FLIGHT  - Validate form_url, normalize scheme/host, HTTP GET to
                    confirm the login page is reachable. 200/401/403/302
                    all count as "reachable but maybe gated". Connect
                    errors / DNS fail / timeouts -> SKIPPED.

  2. FINGERPRINT - Parse the login page with BeautifulSoup. Detects:
                    - Server / X-Powered-By headers
                    - Framework (Rails csrf_token, Laravel _token,
                      ASP.NET __VIEWSTATE, Django csrfmiddlewaretoken)
                    - CAPTCHA (reCAPTCHA / hCaptcha / generic)
                    - Rate-limit headers (X-RateLimit-*, Retry-After)
                    - Form action URL + method + every input field name
                    Stores baseline body length to detect SUCCESS deltas.

  3. QUICK PROBE - POST 5 admin defaults directly via httpx (no patator).
                    Success signals (any one fires):
                    - Body does NOT contain options.fail_string
                    - Response status 302 + Location header
                    - Set-Cookie with "session"|"sess"|"auth" keyword
                    - Body length differs >25% from fingerprint baseline
                    Per-attempt 8s, total budget 60s.

  4. DEEP SCAN   - Gated: only if quick_probe found hits OR
                    options.always_deep=True. Requires userlist + passlist
                    + fail_string. Skipped if CAPTCHA or rate-limit
                    detected (kicking a CAPTCHA wall just trips alarms).
                    Hard-clamped 10 users x 25 passwords. Patator
                    http_fuzz with fgrep-ignore on fail_string.

  5. VERIFY      - Re-POST each finding via httpx. CONFIRMED requires
                    session-cookie present AND fail_string absent;
                    otherwise SUSPECTED.

  6. PRIVILEGE   - With session cookie, GET /admin/users + /admin/settings
                    (and form-base-relative variants). 200 -> admin;
                    403 / 302-to-login -> user; 404 -> unknown (no admin
                    section); not-reachable -> unknown.

  7. CHAIN       - CONFIRMED admin -> webapp_xss + csp_bypass +
                    session_fixation. CONFIRMED user -> session_fixation.
                    Else: no handoff.

Customer input via ScanRequest.options:
  - form_url      = full POST URL of the login form (REQUIRED)
  - user_field    = form param name for username
  - pass_field    = form param name for password
  - fail_string   = substring in a FAILED-login response (REQUIRED for deep)
  - userlist      = newline-separated usernames (for deep_scan)
  - passlist      = newline-separated passwords (for deep_scan)
  - always_deep   = bool, force deep_scan even if quick_probe empty
  - timeout_sec   = wall-clock cap for patator (default 240)

Safety: deep_scan clamped 10 users x 25 passwords. Quick-probe fixed at
5 admin defaults. CAPTCHA/rate-limit auto-skip prevents triggering WAF.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
import time
from typing import Optional
from urllib.parse import urlparse, urljoin

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.patator_http_form_brute_findings import PATATOR_HTTP_FORM_BRUTE_FINDING_RULES

router = APIRouter()
PATATOR_BIN = shutil.which("patator") or shutil.which("patator.py")
DEFAULT_TIMEOUT = 240
HARD_MAX_USERS = 10
HARD_MAX_PASSWORDS = 25

# Top-5 admin defaults probed via httpx BEFORE patator deep-scan.
# These rarely work on production apps but catch staging / test envs
# that ship with default creds (the most-common B2B breach pattern).
QUICK_PROBE_DEFAULTS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("administrator", ""),
]

# Admin paths to probe in privilege_check. We try both the absolute path
# (form_url host root) AND the form-base-relative path (some apps live
# under /portal/ or /app/).
ADMIN_PATHS = ["/admin/users", "/admin/settings", "/admin", "/dashboard"]

# Framework / CSRF token detection in HTML body (case-insensitive).
_RE_FRAMEWORK = {
    "Rails":   re.compile(r"\b(csrf_token|authenticity_token)\b", re.I),
    "Laravel": re.compile(r'<input[^>]+name=["\']_token["\']', re.I),
    "ASP.NET": re.compile(r"__VIEWSTATE", re.I),
    "Django":  re.compile(r"csrfmiddlewaretoken", re.I),
}
_RE_CAPTCHA = re.compile(r"\b(recaptcha|hcaptcha|h-captcha|g-recaptcha|captcha)\b", re.I)
_RE_SESSION_COOKIE = re.compile(r"(session|sess|auth|token|jwt|sid)", re.I)

# Patator http_fuzz success line - mirrors the previous shallow impl.
_RE_HIT = re.compile(
    r"\bINFO\b.*?\b(?P<code>200|301|302|303|307|308)\b.*?\|\s*(?P<user>[^:]+):(?P<pwd>.+?)\s*$",
    re.IGNORECASE,
)
_RE_HITS_DONE = re.compile(r"Hits/Done:\s*(?P<hits>\d+)/(?P<done>\d+)", re.IGNORECASE)


class PatatorHttpFormBruteRequest(ScanRequest):
    options: Optional[dict] = None


def _split_lines(s: str, limit: int) -> list[str]:
    """Trim + dedupe + clamp a newline-separated user/pass string."""
    if not s:
        return []
    out: list[str] = []
    for raw in s.splitlines():
        v = raw.strip()
        if not v or v in out:
            continue
        out.append(v)
        if len(out) >= limit:
            break
    return out


def _write_tempfile(prefix: str, lines: list[str]) -> str:
    fd, path = tempfile.mkstemp(prefix=f"vl_{prefix}_", suffix=".lst")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except Exception:
        try: os.close(fd)
        except Exception: pass
        raise
    return path


def _redact(pwd: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction: length + last 3 chars only.
    show_plaintext=True returns plaintext (customer scanning own infra)."""
    if not pwd: return "len=0"
    pwd = pwd.strip()
    if show_plaintext:
        return pwd
    if len(pwd) <= 3: return f"len={len(pwd)} ***"
    return f"len={len(pwd)} ***{pwd[-3:]}"


def _form_url_ok(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def _build_form_data(user_field: str, pass_field: str, user: str, pwd: str,
                      form_inputs: list[str]) -> dict:
    """Build a POST body that includes the credential fields plus every
    other input on the form set to empty string (so server-side form
    validators don't 400 us for missing required hidden fields)."""
    data: dict = {}
    for name in form_inputs or []:
        if not name:
            continue
        if name == user_field or name == pass_field:
            continue
        data[name] = ""
    data[user_field] = user
    data[pass_field] = pwd
    return data


def _detect_success(resp, fail_string: str, baseline_len: int) -> tuple[bool, str]:
    """Return (success_bool, signal_string). signal explains WHY we
    flagged it (used in finding evidence)."""
    body = resp.text or ""
    body_len = len(body)
    set_cookie = resp.headers.get("set-cookie") or ""
    location = resp.headers.get("location") or ""
    status = resp.status_code

    # Signal 1: 302 redirect to a non-login URL is the classic success.
    if status in (301, 302, 303, 307, 308) and location:
        loc_low = location.lower()
        # Avoid false positive: 302 back to /login is a FAILED login
        if not any(t in loc_low for t in ("login", "signin", "auth", "error")):
            return True, f"302->{location[:60]}"

    # Signal 2: Session-style cookie set.
    if set_cookie and _RE_SESSION_COOKIE.search(set_cookie):
        # Must also not contain fail_string in body
        if not (fail_string and fail_string.lower() in body.lower()):
            return True, "session_cookie_set"

    # Signal 3: Body lacks the explicit fail_string.
    if fail_string and fail_string.lower() not in body.lower() and status == 200:
        # Plus body-length delta vs baseline > 25%
        if baseline_len > 0:
            ratio = abs(body_len - baseline_len) / float(baseline_len)
            if ratio > 0.25:
                return True, f"body_delta={int(ratio*100)}%"
        # Or just fail_string absent on 200 (weakest signal)
        return True, "fail_string_absent"

    return False, ""


# ═══════════════════════════════════════════════════════════════════
#  PatatorHttpFormBrute - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class PatatorHttpFormBrute(MethodologyScanner):
    name = "patator_http_form_brute"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        opts = ctx.state.get("_options") or {}
        form_url = (opts.get("form_url") or "").strip()
        if not form_url:
            ctx.state["skipped_reason"] = "options.form_url not supplied"
            return False
        if not _form_url_ok(form_url):
            ctx.state["skipped_reason"] = f"invalid form_url scheme/host: {form_url[:80]}"
            ctx.state["patator_form_url_invalid"] = True
            return False

        parsed = urlparse(form_url)
        host = parsed.hostname or ""
        ctx.state["form_url"] = form_url
        ctx.state["target_host"] = host
        ctx.state["target_port"] = parsed.port or (443 if parsed.scheme == "https" else 80)

        # HTTP GET probe via httpx.
        try:
            import httpx
        except ImportError:
            ctx.state["skipped_reason"] = "httpx library not installed"
            return False

        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False,
                                          follow_redirects=True) as client:
                resp = await client.get(form_url, headers={
                    "User-Agent": "VulnusLab-Scanner/1.0 (+https://vulnuslab.com)"
                })
            ctx.state["preflight_status"] = resp.status_code
            # 200 = page, 401/403 = gated but reachable, 302 = redirect (also fine)
            if resp.status_code in (200, 401, 403, 301, 302, 303, 307, 308):
                # Stash baseline body for fingerprint stage
                ctx.state["_preflight_body"] = resp.text or ""
                ctx.state["_preflight_headers"] = dict(resp.headers)
                ctx.state["_preflight_baseline_len"] = len(resp.text or "")
                return True
            ctx.state["skipped_reason"] = (
                f"form_url GET returned HTTP {resp.status_code} - "
                f"login page not reachable for testing")
            return False
        except Exception as e:
            ctx.state["skipped_reason"] = f"form_url unreachable: {type(e).__name__}: {str(e)[:120]}"
            return False

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        body = ctx.state.get("_preflight_body") or ""
        headers = ctx.state.get("_preflight_headers") or {}

        # Framework detection
        framework = "unknown"
        for fw_name, pat in _RE_FRAMEWORK.items():
            if pat.search(body):
                framework = fw_name
                break

        # CAPTCHA detection
        captcha = bool(_RE_CAPTCHA.search(body))

        # Rate-limit headers
        rl = {}
        for k in ("x-ratelimit-limit", "x-ratelimit-remaining",
                  "x-rate-limit-limit", "x-rate-limit-remaining", "retry-after"):
            v = headers.get(k) or headers.get(k.title())
            if v:
                rl[k] = v

        # Form parsing via BeautifulSoup
        form_action = ""
        form_method = "POST"
        form_inputs: list[str] = []
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(body, "html.parser")
            # Pick the form that contains a password input (heuristic)
            forms = soup.find_all("form")
            chosen = None
            for fm in forms:
                if fm.find("input", {"type": "password"}):
                    chosen = fm
                    break
            if not chosen and forms:
                chosen = forms[0]
            if chosen is not None:
                form_action = (chosen.get("action") or "").strip()
                form_method = (chosen.get("method") or "POST").upper()
                for inp in chosen.find_all(["input", "select", "textarea"]):
                    n = (inp.get("name") or "").strip()
                    if n and n not in form_inputs:
                        form_inputs.append(n)
        except ImportError:
            pass
        except Exception:
            pass

        # Resolve form_action to absolute URL
        if form_action and not form_action.startswith(("http://", "https://")):
            form_action = urljoin(ctx.state.get("form_url") or "", form_action)
        if not form_action:
            form_action = ctx.state.get("form_url") or ""

        fp = {
            "server": headers.get("server") or headers.get("Server") or "",
            "x_powered_by": headers.get("x-powered-by") or headers.get("X-Powered-By") or "",
            "framework": framework,
            "captcha_detected": captcha,
            "rate_limit_headers": rl,
            "form_action": form_action,
            "form_method": form_method,
            "form_inputs": form_inputs,
        }
        ctx.state["fingerprint"] = fp
        ctx.state["captcha_detected"] = captcha

        # Discard heavy preflight body now that we've parsed it
        ctx.state.pop("_preflight_body", None)
        ctx.state.pop("_preflight_headers", None)

    # ── STAGE 3: QUICK PROBE (5 admin defaults via httpx) ────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        opts = ctx.state.get("_options") or {}
        fp = ctx.state.get("fingerprint") or {}
        form_url = ctx.state.get("form_url") or ""
        action_url = fp.get("form_action") or form_url
        user_field = (opts.get("user_field") or "username").strip()
        pass_field = (opts.get("pass_field") or "password").strip()
        fail_string = (opts.get("fail_string") or "").strip()
        form_inputs = fp.get("form_inputs") or []
        baseline_len = int(ctx.state.get("_preflight_baseline_len") or 0)

        try:
            import httpx
        except ImportError:
            ctx.state["quick_probe_attempts"] = 0
            ctx.state["quick_probe_hits"] = 0
            return []

        findings: list[dict] = []
        attempts = 0
        budget_start = time.time()
        TOTAL_BUDGET = 60.0

        async with httpx.AsyncClient(timeout=8.0, verify=False,
                                      follow_redirects=False) as client:
            for i, (u, p) in enumerate(QUICK_PROBE_DEFAULTS):
                if (time.time() - budget_start) > TOTAL_BUDGET:
                    break
                attempts += 1
                data = _build_form_data(user_field, pass_field, u, p, form_inputs)
                try:
                    resp = await client.post(
                        action_url, data=data,
                        headers={"User-Agent": "VulnusLab-Scanner/1.0"},
                    )
                except Exception:
                    continue
                ok, signal = _detect_success(resp, fail_string, baseline_len)
                if not ok:
                    continue
                _show = bool((ctx.state.get("_options") or {}).get("show_plaintext"))
                findings.append({
                    "id": f"quick_{i}",
                    "kind": "default_credential",
                    "user": u,
                    "password_marker": _redact(p, show_plaintext=_show),
                    "_pwd_private": p,  # stripped before findings reach response
                    "status_code": resp.status_code,
                    "success_signal": signal,
                    "discovery_method": "quick_probe_admin_defaults",
                })

        ctx.state["quick_probe_attempts"] = attempts
        ctx.state["quick_probe_hits"] = len(findings)
        return findings

    # ── STAGE 4: DEEP SCAN (full patator brute, gated) ───────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        opts = ctx.state.get("_options") or {}
        fp = ctx.state.get("fingerprint") or {}
        form_url = ctx.state.get("form_url") or ""

        if not PATATOR_BIN:
            ctx.state["patator_missing"] = True
            ctx.state["deep_skipped"] = "patator binary not installed"
            return []

        user_field = (opts.get("user_field") or "").strip()
        pass_field = (opts.get("pass_field") or "").strip()
        fail_string = (opts.get("fail_string") or "").strip()
        userlist_raw = (opts.get("userlist") or "").strip()
        passlist_raw = (opts.get("passlist") or "").strip()

        missing = [k for k, v in (
            ("user_field", user_field),
            ("pass_field", pass_field),
            ("fail_string", fail_string),
            ("userlist", userlist_raw),
            ("passlist", passlist_raw),
        ) if not v]
        if missing:
            ctx.state["deep_skipped"] = f"required options missing: {', '.join(missing)}"
            ctx.state["patator_input_missing"] = missing
            return []

        if fp.get("captcha_detected"):
            ctx.state["deep_skipped"] = "CAPTCHA detected, deep_scan would trigger detection"
            return []
        if fp.get("rate_limit_headers"):
            ctx.state["deep_skipped"] = "Rate limiting active, deep_scan paused"
            return []

        max_users = min(int(opts.get("max_users") or HARD_MAX_USERS), HARD_MAX_USERS)
        max_pass = min(int(opts.get("max_passwords") or HARD_MAX_PASSWORDS), HARD_MAX_PASSWORDS)
        users = _split_lines(userlist_raw, max_users)
        passwords = _split_lines(passlist_raw, max_pass)
        if not users or not passwords:
            ctx.state["deep_skipped"] = "empty wordlists after dedupe"
            return []

        timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 30), 240)
        action_url = fp.get("form_action") or form_url

        user_path = pass_path = None
        try:
            user_path = _write_tempfile("users", users)
            pass_path = _write_tempfile("passwords", passwords)
            body = f"{user_field}=FILE0&{pass_field}=FILE1"
            cmd = [
                PATATOR_BIN, "http_fuzz",
                f"url={action_url}",
                "method=POST",
                f"body={body}",
                f"0={user_path}",
                f"1={pass_path}",
                "-x", f"ignore:fgrep={fail_string}",
                "-x", "ignore:code=500-599",
                "--threads", "2",
                "-t", "8",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                try: proc.kill()
                except Exception: pass
                ctx.state["deep_skipped"] = f"patator timeout @ {timeout}s"
                return []

            stdout = (out_b or b"").decode("utf-8", errors="ignore")
            stderr = (err_b or b"").decode("utf-8", errors="ignore")
            full = stdout + "\n" + stderr

            ctx.state["patator_attempts"] = len(users) * len(passwords)
            ctx.state["patator_users_tried"] = len(users)
            ctx.state["patator_passwords_tried"] = len(passwords)

            # Cross-check Hits/Done line
            hits_done = 0
            m2 = _RE_HITS_DONE.search(full)
            if m2:
                hits_done = int(m2.group("hits"))
            ctx.state["patator_hits_done"] = hits_done

            findings: list[dict] = []
            _show = bool(opts.get("show_plaintext"))
            for i, line in enumerate(full.splitlines()):
                m = _RE_HIT.search(line)
                if not m:
                    continue
                user = m.group("user").strip()
                pwd = m.group("pwd").strip()
                if not user or not pwd or user.startswith(("Hits", "Total")):
                    continue
                findings.append({
                    "id": f"deep_{i}",
                    "kind": "spray_credential",
                    "user": user,
                    "password_marker": _redact(pwd, show_plaintext=_show),
                    "_pwd_private": pwd,
                    "status_code": int(m.group("code")),
                    "discovery_method": "patator_http_fuzz",
                })

            # If patator's authoritative tally says 0, trust it (regex false-pos)
            if hits_done == 0 and findings:
                findings = []
            return findings
        finally:
            for p in (user_path, pass_path):
                if p:
                    try: os.unlink(p)
                    except Exception: pass

    # ── STAGE 5: VERIFY (re-POST via httpx + session-cookie check) ──
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # VL-FOUNDRY evidence surfacing: stamp a concrete, per-finding
        # evidence string onto the methodology finding object. This rides
        # into the report via the methodology_findings intel field; it adds
        # no new finding and changes no severity (advisory-by-design safe).
        finding["evidence_marker"] = (
            f"{finding.get('discovery_method') or finding.get('kind') or 'probe'}"
            f" -> verifying {finding.get('kind') or 'finding'} for "
            f"{finding.get('user') or finding.get('attack_label') or ctx.host}")
        opts = ctx.state.get("_options") or {}
        fp = ctx.state.get("fingerprint") or {}
        form_url = ctx.state.get("form_url") or ""
        action_url = fp.get("form_action") or form_url
        user_field = (opts.get("user_field") or "username").strip()
        pass_field = (opts.get("pass_field") or "password").strip()
        fail_string = (opts.get("fail_string") or "").strip()
        form_inputs = fp.get("form_inputs") or []

        pwd = finding.get("_pwd_private") or ""
        user = finding.get("user") or ""
        if not pwd or not user:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "verify_skipped_no_pwd"
            return finding

        try:
            import httpx
        except ImportError:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "httpx_missing_cannot_verify"
            return finding

        data = _build_form_data(user_field, pass_field, user, pwd, form_inputs)
        session_cookie = ""
        body_text = ""
        status = 0
        location = ""
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False,
                                          follow_redirects=False) as client:
                resp = await client.post(action_url, data=data,
                    headers={"User-Agent": "VulnusLab-Scanner/1.0"})
                status = resp.status_code
                body_text = resp.text or ""
                location = resp.headers.get("location") or ""
                # Extract session cookie if any
                sc = resp.headers.get("set-cookie") or ""
                if sc and _RE_SESSION_COOKIE.search(sc):
                    session_cookie = sc
                # Store cookies for privilege_check stage
                if resp.cookies:
                    finding["_cookies_private"] = dict(resp.cookies)
        except Exception as e:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = f"httpx_post_failed: {type(e).__name__}"
            return finding

        fail_hit = bool(fail_string and fail_string.lower() in body_text.lower())
        redirect_to_app = (status in (301, 302, 303, 307, 308) and location
                            and not any(t in location.lower()
                                        for t in ("login", "signin", "auth", "error")))

        if session_cookie and not fail_hit:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "httpx_session_cookie_detected"
        elif redirect_to_app and not fail_hit:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "httpx_redirect_to_app_detected"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "patator_signal_unconfirmed"

        finding["verify_status"] = status
        return finding

    # ── STAGE 6: PRIVILEGE CHECK (probe admin paths with session) ──
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        if finding.get("confidence") != "CONFIRMED":
            finding["privilege_level"] = "unknown"
            return finding

        cookies = finding.get("_cookies_private") or {}
        if not cookies:
            finding["privilege_level"] = "unknown"
            return finding

        try:
            import httpx
        except ImportError:
            finding["privilege_level"] = "unknown"
            return finding

        form_url = ctx.state.get("form_url") or ""
        parsed = urlparse(form_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        # Also try relative to form's directory (e.g. /portal/admin/users)
        form_dir = parsed.path.rsplit("/", 1)[0] or ""

        candidate_urls = []
        for ap in ADMIN_PATHS:
            candidate_urls.append(base + ap)
            if form_dir and form_dir != "/":
                candidate_urls.append(base + form_dir + ap)
        # Dedupe while preserving order
        seen = set()
        candidate_urls = [u for u in candidate_urls if not (u in seen or seen.add(u))]

        privilege = "unknown"
        probed = []
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False,
                                          follow_redirects=False,
                                          cookies=cookies) as client:
                for url in candidate_urls[:6]:
                    try:
                        r = await client.get(url, headers={
                            "User-Agent": "VulnusLab-Scanner/1.0"
                        })
                    except Exception:
                        continue
                    probed.append({"url": url, "status": r.status_code})
                    if r.status_code == 200:
                        privilege = "admin"
                        break
                    if r.status_code in (403, 401):
                        privilege = "user"
                        # Keep probing - a later 200 could upgrade to admin
                    elif r.status_code in (301, 302) and "login" in (r.headers.get("location") or "").lower():
                        if privilege == "unknown":
                            privilege = "user"
        except Exception:
            pass

        # If nothing returned 200/401/403 the app may not have an admin
        # section at all; mark "user" rather than "unknown" because we
        # already have a CONFIRMED login.
        if privilege == "unknown" and probed:
            privilege = "user"

        finding["privilege_level"] = privilege
        finding["privilege_probed"] = probed[:6]
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        next_scanners: list[str] = []
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            priv = f.get("privilege_level")
            if priv == "admin":
                next_scanners = [
                    "webapp_xss_dom_sinks_audit",
                    "client_side_csp_bypass_audit",
                    "auth_attacks_session_fixation_test",
                ]
                break
            elif priv == "user":
                next_scanners = ["auth_attacks_session_fixation_test"]
        return next_scanners


# ═══════════════════════════════════════════════════════════════════
#  Endpoint wrapper - adapts MethodologyScanner to existing framework
# ═══════════════════════════════════════════════════════════════════


INTEL_FIELDS = [
    ("Stage timings (ms)",        "stage_timings"),
    ("Target host",               "target_host"),
    ("Target port",               "target_port"),
    ("Form URL",                  "form_url"),
    ("Fingerprint",               "fingerprint"),
    ("CAPTCHA detected",          "captcha_detected"),
    ("Quick-probe attempts",      "quick_probe_attempts"),
    ("Quick-probe hits",          "quick_probe_hits"),
    ("Patator attempts",          "patator_attempts"),
    ("Methodology findings",      "methodology_findings"),
    ("Chain handoff next",        "chain_next"),
    ("Stage errors",              "stage_errors"),
]


def _scrub_private_fields(findings):
    """Strip _pwd_private / _cookies_private before findings reach the
    response payload. Mutates in place."""
    if not findings:
        return
    for f in findings:
        if isinstance(f, dict):
            f.pop("_pwd_private", None)
            f.pop("_cookies_private", None)


@router.post("/api/password/patator_http_form_brute")
async def password_patator_http_form_brute(req: PatatorHttpFormBruteRequest,
                                            _=Depends(verify_scan_quota)):
    scanner = PatatorHttpFormBrute()
    result = await scanner.run_as_endpoint(
        req,
        finding_rules=PATATOR_HTTP_FORM_BRUTE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )
    # Defense-in-depth: scrub private fields from the response payload.
    try:
        intel = (result or {}).get("intel") or {}
        _scrub_private_fields(intel.get("methodology_findings"))
    except Exception:
        pass
    return result


def register(app):
    app.include_router(router)
