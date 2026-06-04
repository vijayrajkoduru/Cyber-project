"""ncrack_rdp_spray - RDP password spray via Ncrack (playbook §1 #5).

Wraps the Kali-installed `ncrack` binary against the target's RDP
service (port 3389 by default). Ncrack is Nmap's network auth tool and
is the most reliable RDP brute-forcer (handles NLA + classic RDP).

Customer input via ScanRequest.options:
  - target              = RDP host/IP (required)
  - options.userlist    = newline-separated usernames (required)
  - options.passlist    = newline-separated passwords (required)
  - options.port        = RDP port override (default 3389)
  - options.timeout_sec = wall-clock cap for ncrack (default 90)
  - options.max_users / options.max_passwords = clamps (defaults 10/25)
"""
from __future__ import annotations
import asyncio
import os
import re
import shutil
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.ncrack_rdp_spray_findings import NCRACK_RDP_SPRAY_FINDING_RULES

router = APIRouter()
NCRACK_BIN = shutil.which("ncrack")
DEFAULT_TIMEOUT = 90
HARD_MAX_USERS = 10
HARD_MAX_PASSWORDS = 25


class NcrackRdpSprayRequest(ScanRequest):
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


# ncrack success format: "Discovered credentials for rdp on 1.2.3.4 3389/tcp:"
#                        "  1.2.3.4 3389/tcp rdp: 'Administrator' 'P@ssw0rd1'"
_RE_SUCCESS = re.compile(
    r"(?P<host>\S+)\s+(?P<port>\d+)/tcp\s+rdp:\s+'(?P<user>[^']*)'\s+'(?P<pwd>[^']*)'",
    re.IGNORECASE,
)


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["ncrack_rdp_spray_total"] = 0
        ctx.source("no-target")
        return
    if not NCRACK_BIN:
        ctx.state["ncrack_rdp_spray_error"] = "ncrack binary not installed"
        ctx.source("ncrack missing")
        return

    opts = ctx.state.get("_options") or {}
    userlist_raw = (opts.get("userlist") or "").strip()
    passlist_raw = (opts.get("passlist") or "").strip()
    if not userlist_raw or not passlist_raw:
        ctx.state["ncrack_rdp_spray_total"] = 0
        ctx.state["ncrack_input_missing"] = True
        ctx.source("missing userlist/passlist")
        return

    max_users = min(int(opts.get("max_users") or HARD_MAX_USERS), HARD_MAX_USERS)
    max_pass = min(int(opts.get("max_passwords") or HARD_MAX_PASSWORDS), HARD_MAX_PASSWORDS)
    users = _split_lines(userlist_raw, max_users)
    passwords = _split_lines(passlist_raw, max_pass)
    if not users or not passwords:
        ctx.state["ncrack_rdp_spray_total"] = 0
        ctx.state["ncrack_input_missing"] = True
        ctx.source("empty wordlists after dedupe")
        return

    port = int(opts.get("port") or 3389)
    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 15), 240)

    user_path: Optional[str] = None
    pass_path: Optional[str] = None
    try:
        user_path = _write_tempfile("users", users)
        pass_path = _write_tempfile("passwords", passwords)
        # ncrack -U users.txt -P pass.txt -p 3389 --connection-limit 4 -f rdp://host
        cmd = [
            NCRACK_BIN,
            "-U", user_path,
            "-P", pass_path,
            "-p", str(port),
            "--connection-limit", "4",
            "-T", "3",                  # moderate timing
            "-f",                       # quit on first valid pair per host
            f"rdp://{target}",
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
            ctx.state["ncrack_rdp_spray_error"] = f"timeout after {timeout}s"
            ctx.state["ncrack_rdp_spray_total"] = 0
            ctx.source(f"timeout @ {timeout}s")
            return

        stdout = (stdout_b or b"").decode("utf-8", errors="ignore")
        stderr = (stderr_b or b"").decode("utf-8", errors="ignore")

        port_closed = False
        combined = (stdout + " " + stderr).lower()
        if ("could not resolve" in combined or
            "no route to host" in combined or
            "connection refused" in combined or
            "host seems down" in combined):
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
                "password_redacted": _redact(m.group("pwd")),
            })

        ctx.state["ncrack_rdp_spray_attempts"] = len(users) * len(passwords)
        ctx.state["ncrack_rdp_spray_target_port"] = port
        ctx.state["ncrack_rdp_spray_users_tried"] = len(users)
        ctx.state["ncrack_rdp_spray_passwords_tried"] = len(passwords)
        ctx.state["ncrack_rdp_successes"] = successes
        ctx.state["ncrack_rdp_spray_total"] = len(successes)
        if port_closed:
            ctx.state["ncrack_rdp_port_closed"] = True
        if successes:
            ctx.source(f"ncrack rdp://{target}:{port} -> {len(successes)} valid login(s)")
        elif port_closed:
            ctx.source(f"ncrack rdp://{target}:{port} -> port unreachable")
        else:
            ctx.source(f"ncrack rdp://{target}:{port} -> 0 valid; "
                       f"{len(users)}u x {len(passwords)}p")
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
    ("Target port",           "ncrack_rdp_spray_target_port"),
    ("Users tried",           "ncrack_rdp_spray_users_tried"),
    ("Passwords tried",       "ncrack_rdp_spray_passwords_tried"),
    ("Total attempts",        "ncrack_rdp_spray_attempts"),
    ("Successful logins",     "ncrack_rdp_successes"),
]


@router.post("/api/password/ncrack_rdp_spray")
async def password_ncrack_rdp_spray(req: NcrackRdpSprayRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="ncrack_rdp_spray",
        gather_func=_gather_with_options,
        finding_rules=NCRACK_RDP_SPRAY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
