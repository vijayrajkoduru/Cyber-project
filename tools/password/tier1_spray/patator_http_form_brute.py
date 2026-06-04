"""patator_http_form_brute - HTTP form login brute via Patator (playbook §1 #6).

Wraps the Kali-installed `patator` binary with its http_fuzz module
against a customer-specified HTML form login endpoint. Patator's
classifier-by-response model is more accurate than hydra's substring
match (you mark fail responses, not success responses, so transient
success states don't poison results).

Customer input via ScanRequest.options:
  - target               = base host/URL (used as Patator's host arg)
  - options.form_url     = full POST URL of the login form (required, e.g.
                            "https://app.example.com/login")
  - options.user_field   = form param name for username (required, e.g. "email")
  - options.pass_field   = form param name for password (required, e.g. "password")
  - options.fail_string  = substring that appears in a FAILED-login response
                            (required, e.g. "Invalid credentials")
  - options.userlist     = newline-separated usernames (required)
  - options.passlist     = newline-separated passwords (required)
  - options.extra_params = optional extra POST params, "k1=v1&k2=v2" form
  - options.timeout_sec  = wall-clock cap (default 90)
  - options.max_users / options.max_passwords = clamps (defaults 5/15)
"""
from __future__ import annotations
import asyncio
import os
import re
import shutil
import tempfile
from urllib.parse import urlparse
from typing import Optional

from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.patator_http_form_brute_findings import PATATOR_HTTP_FORM_BRUTE_FINDING_RULES

router = APIRouter()
PATATOR_BIN = shutil.which("patator") or shutil.which("patator.py")
DEFAULT_TIMEOUT = 90
HARD_MAX_USERS = 5         # Web forms typically lockout faster than ssh/rdp
HARD_MAX_PASSWORDS = 15


class PatatorHttpFormBruteRequest(ScanRequest):
    options: Optional[dict] = None


def _split_lines(s: str, limit: int) -> list[str]:
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


# Patator success line example (http_fuzz):
#   17:24:01 patator  INFO - 0   200 1234:0001  0.123  | user@x.com:Password1
# We classify a hit as any line where the status is shown as accepted
# (Patator prints "+" or shows the entry that did NOT match fail-pattern).
# Reliable extraction: look for "candidate" payload at end + non-skip status.
_RE_HIT = re.compile(
    r"\bINFO\b.*?\b(?P<code>200|301|302|303|307|308)\b.*?\|\s*(?P<user>[^:]+):(?P<pwd>.+?)\s*$",
    re.IGNORECASE,
)
# Patator prints "Hits/Done" line at end - parse for totals
_RE_HITS_DONE = re.compile(r"Hits/Done:\s*(?P<hits>\d+)/(?P<done>\d+)", re.IGNORECASE)


def _form_url_ok(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["patator_http_form_brute_total"] = 0
        ctx.source("no-target")
        return
    if not PATATOR_BIN:
        ctx.state["patator_http_form_brute_error"] = "patator binary not installed"
        ctx.source("patator missing")
        return

    opts = ctx.state.get("_options") or {}
    form_url = (opts.get("form_url") or "").strip()
    user_field = (opts.get("user_field") or "").strip()
    pass_field = (opts.get("pass_field") or "").strip()
    fail_string = (opts.get("fail_string") or "").strip()
    userlist_raw = (opts.get("userlist") or "").strip()
    passlist_raw = (opts.get("passlist") or "").strip()

    missing = [k for k, v in (
        ("form_url", form_url),
        ("user_field", user_field),
        ("pass_field", pass_field),
        ("fail_string", fail_string),
        ("userlist", userlist_raw),
        ("passlist", passlist_raw),
    ) if not v]
    if missing:
        ctx.state["patator_http_form_brute_total"] = 0
        ctx.state["patator_input_missing"] = missing
        ctx.source(f"missing options: {', '.join(missing)}")
        return

    if not _form_url_ok(form_url):
        ctx.state["patator_http_form_brute_total"] = 0
        ctx.state["patator_form_url_invalid"] = True
        ctx.source(f"invalid form_url: {form_url[:60]}")
        return

    max_users = min(int(opts.get("max_users") or HARD_MAX_USERS), HARD_MAX_USERS)
    max_pass = min(int(opts.get("max_passwords") or HARD_MAX_PASSWORDS), HARD_MAX_PASSWORDS)
    users = _split_lines(userlist_raw, max_users)
    passwords = _split_lines(passlist_raw, max_pass)
    if not users or not passwords:
        ctx.state["patator_http_form_brute_total"] = 0
        ctx.state["patator_input_missing"] = ["userlist/passlist empty after dedupe"]
        ctx.source("empty wordlists after dedupe")
        return

    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 15), 240)
    extra_params = (opts.get("extra_params") or "").strip()

    user_path: Optional[str] = None
    pass_path: Optional[str] = None
    try:
        user_path = _write_tempfile("users", users)
        pass_path = _write_tempfile("passwords", passwords)

        # Patator http_fuzz: classify by "fgrep!=" so any response *not*
        # containing fail_string is a candidate hit. Use FILE0=users,
        # FILE1=passwords and reference via 0/1 inside body.
        body = f"{user_field}=FILE0&{pass_field}=FILE1"
        if extra_params:
            body += "&" + extra_params
        # NB: keep cmd args as separate list entries so no shell quoting issues
        cmd = [
            PATATOR_BIN,
            "http_fuzz",
            f"url={form_url}",
            "method=POST",
            f"body={body}",
            f"0={user_path}",
            f"1={pass_path}",
            # Mark as NOT-a-hit anything that contains the fail_string
            f"-x", f"ignore:fgrep={fail_string}",
            # Also ignore network errors so they don't spam findings
            "-x", "ignore:code=500-599",
            "--threads", "4",
            "--timeout", "10",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            ctx.state["patator_http_form_brute_error"] = f"timeout after {timeout}s"
            ctx.state["patator_http_form_brute_total"] = 0
            ctx.source(f"timeout @ {timeout}s")
            return

        stdout = (stdout_b or b"").decode("utf-8", errors="ignore")
        stderr = (stderr_b or b"").decode("utf-8", errors="ignore")
        full = stdout + "\n" + stderr

        successes: list[dict] = []
        for line in full.splitlines():
            m = _RE_HIT.search(line)
            if not m:
                continue
            # Skip the candidate banner / heartbeat lines that don't have a code
            user = m.group("user").strip()
            pwd = m.group("pwd").strip()
            if not user or not pwd or user.startswith("Hits") or user.startswith("Total"):
                continue
            successes.append({
                "url": form_url,
                "user": user,
                "password_redacted": _redact(pwd),
                "status_code": int(m.group("code")),
            })

        # Cross-check against Hits/Done line (patator's authoritative tally)
        hits_done = 0
        m2 = _RE_HITS_DONE.search(full)
        if m2:
            hits_done = int(m2.group("hits"))
        # If Hits/Done says 0 but we matched lines, trust patator and drop them
        if hits_done == 0:
            successes = []

        ctx.state["patator_http_form_brute_attempts"] = len(users) * len(passwords)
        ctx.state["patator_http_form_url"] = form_url
        ctx.state["patator_http_form_user_field"] = user_field
        ctx.state["patator_http_form_pass_field"] = pass_field
        ctx.state["patator_http_form_users_tried"] = len(users)
        ctx.state["patator_http_form_passwords_tried"] = len(passwords)
        ctx.state["patator_http_form_successes"] = successes
        ctx.state["patator_http_form_brute_total"] = len(successes)
        ctx.state["patator_http_form_hits_done"] = hits_done
        if successes:
            ctx.source(f"patator http_fuzz {form_url} -> {len(successes)} valid login(s)")
        else:
            ctx.source(f"patator http_fuzz {form_url} -> 0 valid; "
                       f"{len(users)}u x {len(passwords)}p tried")
    finally:
        for p in (user_path, pass_path):
            if p:
                try: os.unlink(p)
                except Exception: pass


def _redact(pwd: str) -> str:
    if not pwd:
        return "len=0"
    pwd = pwd.strip()
    if len(pwd) <= 3:
        return f"len={len(pwd)} ***"
    return f"len={len(pwd)} ***{pwd[-3:]}"


INTEL_FIELDS = [
    ("Form URL",              "patator_http_form_url"),
    ("Username field",        "patator_http_form_user_field"),
    ("Password field",        "patator_http_form_pass_field"),
    ("Users tried",           "patator_http_form_users_tried"),
    ("Passwords tried",       "patator_http_form_passwords_tried"),
    ("Total attempts",        "patator_http_form_brute_attempts"),
    ("Patator Hits",          "patator_http_form_hits_done"),
    ("Successful logins",     "patator_http_form_successes"),
]


@router.post("/api/password/patator_http_form_brute")
async def password_patator_http_form_brute(req: PatatorHttpFormBruteRequest,
                                            _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="patator_http_form_brute",
        gather_func=_gather_with_options,
        finding_rules=PATATOR_HTTP_FORM_BRUTE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
