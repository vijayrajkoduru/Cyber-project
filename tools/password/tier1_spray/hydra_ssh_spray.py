"""hydra_ssh_spray - SSH password spray via Hydra (playbook §1 #1).

Wraps the Kali-installed `hydra` binary against the target's SSH
service (port 22 by default). Customer supplies a userlist + passlist
as newline-separated strings via ScanRequest.options. Each spray
attempt is logged; every successful login is reported as a CRITICAL
finding (CWE-521 / OWASP A07:2021 - weak password).

Customer input via ScanRequest.options:
  - target              = SSH host/IP (required)
  - options.userlist    = newline-separated usernames (required)
  - options.passlist    = newline-separated passwords (required)
  - options.port        = SSH port override (default 22)
  - options.timeout_sec = wall-clock cap for hydra (default 90)

Safety guard: max 10 users x 25 passwords (250 attempts) per run so a
runaway scan can't lock out every account on the target. Customers can
override via options.max_users / options.max_passwords.
"""
from __future__ import annotations
import asyncio
import os
import re
import shutil
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.hydra_ssh_spray_findings import HYDRA_SSH_SPRAY_FINDING_RULES

router = APIRouter()
HYDRA_BIN = shutil.which("hydra")
DEFAULT_TIMEOUT = 90
HARD_MAX_USERS = 10
HARD_MAX_PASSWORDS = 25


class HydraSshSprayRequest(ScanRequest):
    options: Optional[dict] = None


def _split_lines(s: str, limit: int) -> list[str]:
    """Trim + dedupe + clamp a newline-separated user/pass string."""
    if not s:
        return []
    seen: list[str] = []
    for raw in s.splitlines():
        v = raw.strip()
        if not v:
            continue
        if v in seen:
            continue
        seen.append(v)
        if len(seen) >= limit:
            break
    return seen


def _write_tempfile(prefix: str, lines: list[str]) -> str:
    fd, path = tempfile.mkstemp(prefix=f"vl_{prefix}_", suffix=".lst")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        raise
    return path


_RE_SUCCESS = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<svc>ssh)\]\s+host:\s*(?P<host>\S+)\s+login:\s*(?P<user>\S+)\s+password:\s*(?P<pwd>.+)$",
    re.IGNORECASE,
)


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["hydra_ssh_spray_total"] = 0
        ctx.source("no-target")
        return
    if not HYDRA_BIN:
        ctx.state["hydra_ssh_spray_error"] = "hydra binary not installed"
        ctx.source("hydra missing")
        return

    opts = ctx.state.get("_options") or {}
    userlist_raw = (opts.get("userlist") or "").strip()
    passlist_raw = (opts.get("passlist") or "").strip()
    if not userlist_raw or not passlist_raw:
        ctx.state["hydra_ssh_spray_total"] = 0
        ctx.state["hydra_input_missing"] = True
        ctx.source("missing userlist/passlist")
        return

    max_users = min(int(opts.get("max_users") or HARD_MAX_USERS), HARD_MAX_USERS)
    max_pass = min(int(opts.get("max_passwords") or HARD_MAX_PASSWORDS), HARD_MAX_PASSWORDS)
    users = _split_lines(userlist_raw, max_users)
    passwords = _split_lines(passlist_raw, max_pass)
    if not users or not passwords:
        ctx.state["hydra_ssh_spray_total"] = 0
        ctx.state["hydra_input_missing"] = True
        ctx.source("empty wordlists after dedupe")
        return

    port = int(opts.get("port") or 22)
    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 15), 240)

    user_path: Optional[str] = None
    pass_path: Optional[str] = None
    try:
        user_path = _write_tempfile("users", users)
        pass_path = _write_tempfile("passwords", passwords)
        # hydra -L users.txt -P pass.txt -s 22 -t 4 -f -o /dev/null -I -V -e nsr ssh://host
        cmd = [
            HYDRA_BIN,
            "-L", user_path,
            "-P", pass_path,
            "-s", str(port),
            "-t", "4",          # parallel tasks (low to avoid SSH MaxStartups blocks)
            "-w", "10",         # per-attempt wait
            "-I",               # ignore restore file
            "-f",               # stop after first valid login per pair
            target,
            "ssh",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "HYDRA_PROXY_HTTP": "", "HYDRA_PROXY": ""},
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            ctx.state["hydra_ssh_spray_error"] = f"timeout after {timeout}s"
            ctx.state["hydra_ssh_spray_total"] = 0
            ctx.source(f"timeout @ {timeout}s")
            return

        stdout = (stdout_b or b"").decode("utf-8", errors="ignore")
        stderr = (stderr_b or b"").decode("utf-8", errors="ignore")

        # Detect port-closed / connection refused -> SKIPPED-style INFO
        port_closed = False
        low_se = stderr.lower() + " " + stdout.lower()
        if ("connection refused" in low_se or
            "could not resolve" in low_se or
            "all children were disabled" in low_se):
            port_closed = True

        successes: list[dict] = []
        for line in stdout.splitlines():
            m = _RE_SUCCESS.search(line)
            if not m:
                continue
            successes.append({
                "host": m.group("host"),
                "port": int(m.group("port")),
                "user": m.group("user"),
                # Redact password to last-3 + length so PDF doesn't leak creds
                "password_redacted": _redact(m.group("pwd").strip()),
            })

        ctx.state["hydra_ssh_spray_attempts"] = len(users) * len(passwords)
        ctx.state["hydra_ssh_spray_target_port"] = port
        ctx.state["hydra_ssh_spray_users_tried"] = len(users)
        ctx.state["hydra_ssh_spray_passwords_tried"] = len(passwords)
        ctx.state["hydra_ssh_successes"] = successes
        ctx.state["hydra_ssh_spray_total"] = len(successes)
        if port_closed:
            ctx.state["hydra_ssh_port_closed"] = True
        if successes:
            ctx.source(f"hydra ssh://{target}:{port} -> {len(successes)} valid login(s)")
        elif port_closed:
            ctx.source(f"hydra ssh://{target}:{port} -> port unreachable")
        else:
            ctx.source(f"hydra ssh://{target}:{port} -> 0 valid; "
                       f"{len(users)}u x {len(passwords)}p tried")
    finally:
        for p in (user_path, pass_path):
            if p:
                try: os.unlink(p)
                except Exception: pass


def _redact(pwd: str) -> str:
    """Customer-safe redaction: length + last 3 chars only.
    e.g. 'Summer2025!' -> 'len=11 *****25!'"""
    if not pwd:
        return "len=0"
    pwd = pwd.strip()
    if len(pwd) <= 3:
        return f"len={len(pwd)} ***"
    return f"len={len(pwd)} ***{pwd[-3:]}"


INTEL_FIELDS = [
    ("Target port",           "hydra_ssh_spray_target_port"),
    ("Users tried",           "hydra_ssh_spray_users_tried"),
    ("Passwords tried",       "hydra_ssh_spray_passwords_tried"),
    ("Total attempts",        "hydra_ssh_spray_attempts"),
    ("Successful logins",     "hydra_ssh_successes"),
]


@router.post("/api/password/hydra_ssh_spray")
async def password_hydra_ssh_spray(req: HydraSshSprayRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="hydra_ssh_spray",
        gather_func=_gather_with_options,
        finding_rules=HYDRA_SSH_SPRAY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
