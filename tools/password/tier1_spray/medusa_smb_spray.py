"""medusa_smb_spray - SMB password spray via Medusa (playbook §1 #4).

Wraps the Kali-installed `medusa` binary against the target's SMB
service (port 445). Medusa's smbnt module is the fastest portable SMB
brute (parallel thread model). On modern Windows / Samba, SMB signing +
account lockout usually defeat this, but legacy fileshares and IoT NAS
boxes still fall over.

Customer input via ScanRequest.options:
  - target              = SMB host/IP (required)
  - options.userlist    = newline-separated usernames (required)
  - options.passlist    = newline-separated passwords (required)
  - options.port        = SMB port override (default 445)
  - options.timeout_sec = wall-clock cap for medusa (default 90)
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
from tools._payloads.medusa_smb_spray_findings import MEDUSA_SMB_SPRAY_FINDING_RULES

router = APIRouter()
MEDUSA_BIN = shutil.which("medusa")
DEFAULT_TIMEOUT = 90
HARD_MAX_USERS = 10
HARD_MAX_PASSWORDS = 25


class MedusaSmbSprayRequest(ScanRequest):
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


# Medusa success line: "ACCOUNT FOUND: [smbnt] Host: 1.2.3.4 User: admin Password: P@ss [SUCCESS]"
_RE_SUCCESS = re.compile(
    r"ACCOUNT\s+FOUND:\s*\[smbnt\]\s+Host:\s*(?P<host>\S+)\s+User:\s*(?P<user>\S+)\s+"
    r"Password:\s*(?P<pwd>.+?)\s+\[SUCCESS\]",
    re.IGNORECASE,
)


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["medusa_smb_spray_total"] = 0
        ctx.source("no-target")
        return
    if not MEDUSA_BIN:
        ctx.state["medusa_smb_spray_error"] = "medusa binary not installed"
        ctx.source("medusa missing")
        return

    opts = ctx.state.get("_options") or {}
    userlist_raw = (opts.get("userlist") or "").strip()
    passlist_raw = (opts.get("passlist") or "").strip()
    if not userlist_raw or not passlist_raw:
        ctx.state["medusa_smb_spray_total"] = 0
        ctx.state["medusa_input_missing"] = True
        ctx.source("missing userlist/passlist")
        return

    max_users = min(int(opts.get("max_users") or HARD_MAX_USERS), HARD_MAX_USERS)
    max_pass = min(int(opts.get("max_passwords") or HARD_MAX_PASSWORDS), HARD_MAX_PASSWORDS)
    users = _split_lines(userlist_raw, max_users)
    passwords = _split_lines(passlist_raw, max_pass)
    if not users or not passwords:
        ctx.state["medusa_smb_spray_total"] = 0
        ctx.state["medusa_input_missing"] = True
        ctx.source("empty wordlists after dedupe")
        return

    port = int(opts.get("port") or 445)
    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 15), 240)

    user_path: Optional[str] = None
    pass_path: Optional[str] = None
    try:
        user_path = _write_tempfile("users", users)
        pass_path = _write_tempfile("passwords", passwords)
        # medusa -h host -U users.txt -P passwords.txt -M smbnt -n 445 -t 4 -f
        cmd = [
            MEDUSA_BIN,
            "-h", target,
            "-U", user_path,
            "-P", pass_path,
            "-M", "smbnt",
            "-n", str(port),
            "-t", "4",          # 4 parallel logins (gentle)
            "-f",               # stop scanning host after first valid pair
            "-r", "1",          # 1s retry delay
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
            ctx.state["medusa_smb_spray_error"] = f"timeout after {timeout}s"
            ctx.state["medusa_smb_spray_total"] = 0
            ctx.source(f"timeout @ {timeout}s")
            return

        stdout = (stdout_b or b"").decode("utf-8", errors="ignore")
        stderr = (stderr_b or b"").decode("utf-8", errors="ignore")

        port_closed = False
        combined = (stdout + " " + stderr).lower()
        if ("connection refused" in combined or
            "no route to host" in combined or
            "connection failed" in combined or
            "no host found" in combined):
            port_closed = True
        # Detect lockout warning so we report it honestly
        lockout_hit = ("account lockout" in combined or
                       "account has been locked" in combined or
                       "policy_account_disabled" in combined)

        successes: list[dict] = []
        for line in stdout.splitlines():
            m = _RE_SUCCESS.search(line)
            if not m:
                continue
            successes.append({
                "host": m.group("host"),
                "user": m.group("user"),
                "password_redacted": _redact(m.group("pwd")),
            })

        ctx.state["medusa_smb_spray_attempts"] = len(users) * len(passwords)
        ctx.state["medusa_smb_spray_target_port"] = port
        ctx.state["medusa_smb_spray_users_tried"] = len(users)
        ctx.state["medusa_smb_spray_passwords_tried"] = len(passwords)
        ctx.state["medusa_smb_successes"] = successes
        ctx.state["medusa_smb_spray_total"] = len(successes)
        if port_closed:
            ctx.state["medusa_smb_port_closed"] = True
        if lockout_hit:
            ctx.state["medusa_smb_lockout_hit"] = True
        if successes:
            ctx.source(f"medusa smbnt://{target}:{port} -> {len(successes)} valid login(s)")
        elif port_closed:
            ctx.source(f"medusa smbnt://{target}:{port} -> port unreachable")
        elif lockout_hit:
            ctx.source(f"medusa smbnt://{target}:{port} -> account lockout triggered")
        else:
            ctx.source(f"medusa smbnt://{target}:{port} -> 0 valid; "
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
    ("Target port",           "medusa_smb_spray_target_port"),
    ("Users tried",           "medusa_smb_spray_users_tried"),
    ("Passwords tried",       "medusa_smb_spray_passwords_tried"),
    ("Total attempts",        "medusa_smb_spray_attempts"),
    ("Successful logins",     "medusa_smb_successes"),
]


@router.post("/api/password/medusa_smb_spray")
async def password_medusa_smb_spray(req: MedusaSmbSprayRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="medusa_smb_spray",
        gather_func=_gather_with_options,
        finding_rules=MEDUSA_SMB_SPRAY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
